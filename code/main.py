import json, datetime
from ldap3.utils.log import *
from connector import LDAP_Connector, CaseInsensitiveDict
from data import LDAP_Type
from logger import logging


## Служебные функции
#   Количество вхождений ou (для орделения порядка создания OU)
def count_ou_occurrences(dn):
    return dn.count("ou=")

#   Изменение имени группы в формат CN=OU_GroupName
def rename_group(group_dn):
    elements = group_dn.split(',')
    if elements[1].split('=')[1] not in elements[0]:
        first_element =  'cn=' + elements[1].split('=')[1] + '_' + elements[0].split('=')[1]
        elements[0] = f"{first_element}"
    new_string = ','.join(elements)
    return new_string

#   Маппинг атрибутов
def map_attributes(attribute_mapping_user, source_attributes):
    mapped_attributes = CaseInsensitiveDict()
    for target_attr, source_attr  in attribute_mapping_user.items():
        if source_attributes[source_attr] and source_attributes[source_attr] != '':
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
                                            ldap_type=LDAP_Type.Edirectory, \
                                                source_root_dn=json_config['READ_ROOT_DN'], \
                                                    dest_root_dn=json_config['WRITE_ROOT_DN'])
    samba_connector = LDAP_Connector(fqdn=json_config['WRITE_DOMAIN_DC_FQDN'], \
                                        ldap_manager=json_config['WRITE_DOMAIN_ADMIN_USERNAME'], \
                                        ldap_password=json_config['WRITE_ADMIN_PASSWORD'], \
                                            ldap_type=LDAP_Type.SambaDC, \
                                                source_root_dn=json_config['READ_ROOT_DN'], \
                                                    dest_root_dn=json_config['WRITE_ROOT_DN'])

## Список OU для переноса
    list_ou = json_config['MIGRATION_LIST_OU']
## Search base сервера источника и целевого сервера
    source_search_base=json_config['MIGRATION_SEARCH_BASE']
    dest_search_base=samba_connector.convert_dn(source_search_base)

## Поиск объектов, учитывая фильтрацию по верхнеуровневым OU 
#  То есть если задан MIGRATION_SEARCH_BASE: "o=gazprom", а нужно копировать только ou=HQ,o=gazprom и ou=BrunchOffice01,o=gazprom
#  то дополнительно это нужно задать в MIGRATION_LIST_OU "MIGRATION_LIST_OU": ["ou=HQ", "ou=BrunchOffice01"]  
    source_ou_list, source_groups_list, source_user_list = [], [], []
    for ou in list_ou:
        source_search_base_ou = f'{ou + "," if ou else ""}{source_search_base}'
        source_ou_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_OU'], \
                                                          search_base=source_search_base_ou, \
                                                            attribute_list=list(source_attributes_ou)))
        source_groups_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILER_GROUP'], \
                                                              search_base=source_search_base_ou, \
                                                                attribute_list=list(source_attributes_group)))
        source_user_list.extend(edir_connector.search_records(filter=json_config['LDAP_FILTER_USER'], \
                                                            search_base=source_search_base_ou, \
                                                                attribute_list=list(source_attributes_user)))

## Копирование структуры OU
    logging.info(f"************* Миграция OU {datetime.datetime.now()} ************************")
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

## Копирование пользователей
    logging.info(f"************* Миграция пользователей {datetime.datetime.now()} *************")
    for user in source_user_list:
        new_user = samba_connector.convert_dn(user.entry_dn)
        user_mapped_attributes = map_attributes(attribute_mapping_user, user)
        samba_connector.add_user_record(source_new_dn=new_user, \
                                        set_default_password=True, \
                                            disable_user=json_config['DISABLE_USER_AFTER_CREATION'],\
                                                default_password=json_config['DEFAULT_USER_MIGRATION_PASSWORD'], \
                                                    source_attributes=user_mapped_attributes, \
                                                        dest_attributes=dest_attributes_user)

## Подготока списка пользоватлей целевого сервера для последующего сравнения с сервером источником, добавления их в группы, и удаления 
#  и удаления
    dest_ou_list, dest_groups_list, dest_user_list = [], [], []
    for ou in list_ou:
        dest_search_base_ou = f'{ou + "," if ou else ""}{dest_search_base}'
        dest_ou_list.extend(samba_connector.search_records(filter=json_config['LDAP_FILER_OU'], \
                                                          search_base=dest_search_base_ou, \
                                                            attribute_list=['novellGUID']))
        dest_groups_list.extend(samba_connector.search_records(filter=json_config['LDAP_FILER_GROUP'], \
                                                              search_base=dest_search_base_ou, \
                                                                attribute_list=['novellGUID']))
        dest_user_list.extend(samba_connector.search_records(filter=json_config['LDAP_FILTER_USER'], \
                                                            search_base=dest_search_base_ou, \
                                                                attribute_list=['novellGUID']))


## Копирование групп и добавление в группу пользователей
    logging.info(f"************* Миграция групп {datetime.datetime.now()} *********************")
    # Удаление атрибута member из списка атрибутов на целевом сервере, так как добавление членов выполняется после создания группы
    dest_attributes_group.remove('member')
    # Пользователи на целевом сервере
    set_dest_user_list = set(entry.entry_dn.lower() for entry in dest_user_list)

    for group in source_groups_list:
        # Переименование группы в формат CN_GroupName
        new_group_dn = rename_group(samba_connector.convert_dn(group.entry_dn))
        # Задание CN для группы в формат CN_GroupName
        new_cn = new_group_dn.split(',')[0].split('=')[1]
        # Маппинг атрибутов группы
        group_mapped_attributes = map_attributes(attribute_mapping_group, group)
        group_mapped_attributes['cn'] = new_cn
        # Удаление атрибута member, так как добавление членов в группу обрабатывается после создания группы
        group_mapped_attributes.pop('member', None)
        # Создание группы
        samba_connector.add_group_record(source_new_dn=new_group_dn, \
                                         source_attributes=group_mapped_attributes, \
                                            dest_attributes=dest_attributes_group)
        # Добавление пользователей в группу, если она существует
        if samba_connector.result['description'] == 'success':
            # Подготовка списка членов для добавления в группу, проверка что пол
            source_group_members = set(samba_connector.convert_dn(group_member).lower() for group_member in list(group['member']))
            # Находим только тех пользователей, которые есть целевом сервере
            common_users = source_group_members & set_dest_user_list
            # Вывод информации, каких пользователей нет
            not_on_dest_server = source_group_members.difference(common_users)
            if not_on_dest_server:
                logging.warning(f'Для группы {new_group_dn} нет пользователей на целевом сервере: {not_on_dest_server} ')
            samba_connector.update_user_membership(source_group_members = common_users, \
                                               group_dn=new_group_dn)

## Удаление записей

    # Удаление групп
    dest_groups = set(str(entry['novellGUID']) for entry in dest_groups_list)
    source_groups = set(str(entry['GUID']) for entry in source_groups_list)
    delete_groups = dest_groups.difference(source_groups)
    if delete_groups:
        logging.info(f"************* Удаление групп {datetime.datetime.now()} *********************")
        samba_connector.delete_records(records=delete_groups)

    # Удаление пользователей
    dest_users = set(str(entry['novellGUID']) for entry in dest_user_list)
    source_users = set(str(entry['GUID']) for entry in source_user_list)
    delete_users = dest_users.difference(source_users)
    if delete_users:
        logging.info(f"************* Удаление пользователей {datetime.datetime.now()} *************")
        samba_connector.delete_records(records=delete_users)

    # Удаление OU
    dest_ou = set(str(entry['novellGUID']) for entry in dest_ou_list)
    source_ou = set(str(entry['GUID']) for entry in source_ou_list)
    delete_ou = dest_ou.difference(source_ou)
    if delete_ou:
        logging.info(f"************* Удаление OU {datetime.datetime.now()} ************************")
        samba_connector.delete_records(records=delete_ou)

__main__()