import json, datetime
from ldap3.utils.log import *
from connector import LDAP_Connector, CaseInsensitiveDict
from data import LDAP_Type
from logger import logging
# from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups

## Служебные функции
#   Количество вхождений ou (для орделения порядка создания OU)
def count_ou_occurrences(dn):
    return dn.count("ou=")

#   Изменение имени группы в формат CN=CN.OU
def rename_group(group_dn):
    elements = group_dn.split(',')
    first_element = elements[0] + '.' + elements[1].split('=')[1]
    elements[0] = f"{first_element}"
    new_string = ','.join(elements)
    return new_string

#   Маппинг атрибутов
def map_attributes(attribute_mapping_user, source_attributes):
    mapped_attributes = CaseInsensitiveDict()
    for target_attr, source_attr  in attribute_mapping_user.items():
        if source_attributes[source_attr] and source_attributes[source_attr] is not None:
            mapped_attributes[target_attr] = str(source_attributes[source_attr])
    return mapped_attributes


def __main__():

## Загрузка конфигурации
    with open('config.json', 'r', encoding='utf-8') as file:
        json_config = json.load(file)
        pass

## 
    attribute_mapping_ou = json_config['MappingAttr']['OU']
    attribute_mapping_user = json_config['MappingAttr']['User']
    attribute_mapping_group = json_config['MappingAttr']['Group']
##
    # Список атрибутов источника
    source_attributes_ou = attribute_mapping_ou.values()
    source_attributes_group = attribute_mapping_group.values()
    source_attributes_user = attribute_mapping_user.values()
    # Список атрибутов целевого сервера
    dest_attributes_ou = attribute_mapping_ou.keys()
    dest_attributes_user = attribute_mapping_user.keys()
    dest_attributes_group = list(attribute_mapping_group.keys())



## Подключение к LDAP серверам
    edir_connector = LDAP_Connector(fqdn=json_config['READ_DOMAIN_DC_FQDN'], \
                                    ldap_manager=json_config['READ_DOMAIN_ADMIN_USERNAME'], \
                                        ldap_password=json_config['READ_ADMIN_PASSWORD'], \
                                            ldap_type=LDAP_Type.Edirectory)
    samba_connector = LDAP_Connector(fqdn=json_config['WRITE_DOMAIN_DC_FQDN'], \
                                     ldap_manager=json_config['WRITE_DOMAIN_ADMIN_USERNAME'], \
                                        ldap_password=json_config['WRITE_ADMIN_PASSWORD'], \
                                            ldap_type=LDAP_Type.SambaDC)



## Поиск объектов, учитывая фильтрацию по верхнеуровневым OU 
#  То есть если задан MIGRATION_SEARCH_BASE: "o=gazprom", а нужно копировать только ou=HQ,o=gazprom и ou=BrunchOffice01,o=gazprom
#  то дополнительно это нужно задать в MIGRATION_LIST_OU "MIGRATION_LIST_OU": ["ou=HQ", "ou=BrunchOffice01"]  
    list_ou = json_config['MIGRATION_LIST_OU']
    search_base=json_config['MIGRATION_SEARCH_BASE']
    source_ou_list, source_groups_list, source_user_list = [], [], []
    for ou in list_ou:
        search_base_ou = f'{ou + "," if ou else ""}{search_base}'
        source_ou_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_OU'], \
                                                          search_base=search_base_ou, \
                                                            attribute_list=list(source_attributes_ou)))
        source_groups_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_GROUP'], \
                                                              search_base=search_base_ou, \
                                                                attribute_list=list(source_attributes_group)))
        source_user_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILTER_USER'], \
                                                            search_base=search_base_ou, \
                                                                attribute_list=list(source_attributes_user)))



## Копирование структуры OU
    logging.info(f"************* Миграция OU {datetime.datetime.now()} *************")
    new_ou_dict={}
    for ou in source_ou_list:
        new_ou = samba_connector.convert_dn(ou.entry_dn)
        ou_mapped_attributes = map_attributes(attribute_mapping_ou, ou)
        new_ou_dict[new_ou] = ou_mapped_attributes
    key_sort = sorted(new_ou_dict.keys(), key=count_ou_occurrences)
    sorted_new_ou_dict = {i: new_ou_dict[i] for i in key_sort}
    for new_ou, attr in sorted_new_ou_dict.items():
        samba_connector.add_ou_record(source_new_dn=new_ou, \
                                      source_attributes=attr, \
                                        dest_attributes=dest_attributes_ou)
    pass


## Копирование пользователей
    logging.info(f"************* Миграция пользователей {datetime.datetime.now()} *************")
    for user in source_user_list:
        new_user = samba_connector.convert_dn(user.entry_dn)
        user_mapped_attributes = map_attributes(attribute_mapping_user, user)
        samba_connector.add_user_record(source_new_dn=new_user, \
                                        set_default_password=True, \
                                            default_password=json_config['DEFAULT_USER_MIGRATION_PASSWORD'], \
                                                source_attributes=user_mapped_attributes, \
                                                    dest_attributes=dest_attributes_user)
    pass



## Копирование групп и добавление в группу пользователей
    logging.info(f"************* Миграция групп {datetime.datetime.now()} *************")
    dest_attributes_group.remove('member')
    for group in source_groups_list:
        new_group_dn = rename_group(samba_connector.convert_dn(group.entry_dn))
        new_cn = new_group_dn.split(',')[0].split('=')[1]
        group_mapped_attributes = map_attributes(attribute_mapping_group, group)
        group_mapped_attributes['cn'] = new_cn
        # Подготовка списка членов группы
        dest_group_members = list(samba_connector.convert_dn(group_member) for group_member in list(group['member']))
        # Удаление атрибута member, так как добавление членов в группу обрабатывается после создания группы
        group_mapped_attributes.pop('member', None)
        # Создание группы
        samba_connector.add_group_record(source_new_dn=new_group_dn, \
                                         source_attributes=group_mapped_attributes, \
                                            dest_attributes=dest_attributes_group)
        # Добавление пользователей в группу, если она существует
        if samba_connector.result['description'] == 'success':
            samba_connector.add_users_to_group(members_dn = dest_group_members, \
                                               group_dn=new_group_dn)
    pass

## Удаление записей
    list_ou = json_config['MIGRATION_LIST_OU']
    search_base=json_config['MIGRATION_SEARCH_BASE']
    source_ou_list, source_groups_list, source_user_list = [], [], []
    # for ou in list_ou:
    #     search_base_ou = f'{ou + "," if ou else ""}{search_base}'
    #     source_ou_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_OU'], \
    #                                                       search_base=search_base_ou, \
    #                                                         attribute_list=list(source_attributes_ou)))
    #     source_groups_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_GROUP'], \
    #                                                           search_base=search_base_ou, \
    #                                                             attribute_list=list(source_attributes_group)))
    #     source_user_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILTER_USER'], \
    #                                                         search_base=search_base_ou, \
    #                                                             attribute_list=list(source_attributes_user)))
    # samba_records = samba_connector.search_records(filter='(novellGUID=*)', \
    #                                                       search_base=samba_connector.server.get_split_fqdn(), \
    #                                                         attribute_list='novellGUID')
    # list_samba_records = []
    # for record in samba_records:
    #     search = '(GUID={})'.format(record.novellGUID)
    #     edir_record = edir_connector.search_records(filter=search, search_base=search_base)
    #     if not edir_record:
    #         samba_connector.delete_records(dn=record.entry_dn)


__main__()