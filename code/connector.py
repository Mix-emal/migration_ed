from ldap3 import Connection
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPInvalidDnError
from data import Server_Data, LDAP_Type
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
from logger import logging


## Класс определяет регистронезависимый словарь
class CaseInsensitiveDict(dict):
    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    

## Основной класс
class LDAP_Connector (Connection):
    """
    A class to represent connection to LDAP.

    Attributes
    ----------
    fqdn : str
        Fully Qualified Domain Name of the ldap server
    ldap_type : LDAP_Type
        LDAP type of the server
    ldap_manager: str
        Account for LDAP connection, REDOS\Administrator, Administrator@redos.croc
    ldap_password: str
        Account password

    Methods
    -------
    split_fqdn():
        Return server FQDN into, example dc01.croc.demo -> "DC=croc, DC=demo"
    """

    def __init__(self, fqdn: str, ldap_type: LDAP_Type, ldap_manager: str, ldap_password: str):
        """
        Init attributes for creating Server Object

        Parameters
        ----------
            fqdn : str
                Fully Qualified Domain Name of the ldap server
            ldap_type : LDAP_Type
                LDAP type of the server
            ldap_manager: str
                LDAP Administrator account
            ldap_password: str
                Account password
        
        Returns
        -------
        Connection object
        """

        self.__ldap_manager = ldap_manager
        self.__ldap_password = ldap_password
        self.server_data = Server_Data(fqdn, ldap_type)

        try:
            super().__init__(server=self.server_data, user=self.__ldap_manager, password=self.__ldap_password)
            super().bind()
            pass
        except LDAPBindError as error:
            logging.critical(error)
            pass
        pass



    @staticmethod
    def __get_changed_attr(source_attr_dict, dest_attr_dict):
        result_dictionary = {}
        for key in dest_attr_dict.keys():
            if key in source_attr_dict:
                if source_attr_dict[key] != dest_attr_dict[key]:
                    result_dictionary[key] = ['MODIFY_REPLACE', (source_attr_dict[key])]
            else:
                if dest_attr_dict[key] != '[]':
                    result_dictionary[key] = ['MODIFY_REPLACE', list('')]
        return result_dictionary
    


    @staticmethod
    def __lower_case_cn_ou_dc(input_string: str):
        input_string = input_string.replace('CN=', 'cn=')
        input_string = input_string.replace('OU=', 'ou=')
        input_string = input_string.replace('DC=', 'dc=')
        return input_string



    def __is_record_exist(self, search_filer: str, attr: list):
        search = '(novellGUID={})'.format(search_filer)
        records = self.search_records(filter=search, search_base=self.server.get_split_fqdn(), attrubite_list=attr)
        return records



    def search_records(self, filter: str, search_base: str, attrubite_list=['distinguishedName']):
        self.search(search_base=search_base, search_filter=filter, attributes=attrubite_list)
        return self.entries



    def convert_dn(self, source_dn, destination_base_dn):
        parts = str(source_dn).split(',')
        converted_parts = []
        for part in parts:
            key, value = part.split('=')
            if key.lower() == 'o':
                converted_part = f"{destination_base_dn}"
            elif key.lower() == 'dc':
                converted_part = f"{destination_base_dn}"
            else:
                converted_part = f"{key}={value}"
            converted_parts.append(converted_part)
        destination_dn = ','.join(converted_parts)
        return destination_dn



    def compare_records(self, source_dn: str, source_attr: dict, dest_object):
    ## Подготовка данных для сравнения: DN и атрибуты
        #   Данные с сервера истончника
        source_dn_list = source_dn.split(',')
        source_cn = self.__lower_case_cn_ou_dc(source_dn_list[0])
        source_container = self.__lower_case_cn_ou_dc(','.join(source_dn_list[1:]))
        #   Данные на целевом сервере
        dest_attr_dict = CaseInsensitiveDict()
        for entry in dest_object.entry_attributes:
            dest_attr_dict[entry] = str(dest_object[entry])
        dest_dn_list = dest_object.entry_dn.split(',')
        dest_cn = self.__lower_case_cn_ou_dc(dest_dn_list[0])
        dest_container = self.__lower_case_cn_ou_dc(','.join(dest_dn_list[1:]))
    ## Сверка и обновление DN
        if dest_cn == source_cn and source_container != dest_container:
            self.modify_dn(dest_object.entry_dn, dest_cn, new_superior=source_container)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' перемещен в контейнер ' + source_container)
            else:
                logging.error('DN: ' + dest_object.entry_dn + '. Ошибка перемещения: ' + self.result['message'] )
        elif dest_cn != source_cn and source_container == dest_container:
            self.modify_dn(','.join([dest_cn, dest_container]), source_cn)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' переименован в ' + source_cn)
            else:
                logging.error('DN: ' + dest_object.entry_dn + ' при переименовании произошла ошибка: ' + self.result['message'] )
        elif dest_cn != source_cn and source_container != dest_container:
            self.modify_dn(dest_object.entry_dn, dest_cn, new_superior=source_container)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' перемещен в контейнер ' + source_container)
            else:
                logging.error('DN: ' + dest_object.entry_dn + '. Ошибка перемещения: ' + self.result['message'] )
            self.modify_dn(','.join([dest_cn, source_container]), source_cn)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' переименован в ' + source_cn)
            else:
                logging.error('DN: ' + dest_object.entry_dn + ' при переименовании произошла ошибка: ' + self.result['message'] )
    ## Сверка и обновление атрибутов    
        compare_attributes = self.__get_changed_attr(source_attr, dest_attr_dict)
        if compare_attributes:
            self.modify(source_dn, compare_attributes)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' обновлены атрибуты: ' + ' ,'.join(list(compare_attributes.keys())))
            else:
                logging.error('DN: ' + dest_object.entry_dn + ' ошибка при обновлении атрибутов ' + ' ,'.join(list(compare_attributes.keys())) + ': ' + self.result['message'] )
        pass



    def add_ou_record(self, source_new_dn: str, \
                      source_attributes: dict, \
                        dest_attributes: list, \
                            object_class = ['organizationalUnit']):
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        if not dest_dn:
            self.add(dn=source_new_dn, object_class = object_class, attributes=source_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('OU DN: ' + source_new_dn + ' добавлен')
            else:
                logging.error('OU DN: ' + source_new_dn + ' не создан. Ошибка: ' + self.result['message'] )
            pass
        else:
            logging.info('OU DN: ' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])
            else:
                logging.error('OU DN: ' + source_new_dn + ' Существует больше одного объекта с novellGUID: ' + source_attributes['novellGUID'])
        pass
    pass



    def add_user_record(self, source_new_dn: str, \
                        default_password: str, \
                            source_attributes: dict, \
                                dest_attributes: list, \
                                    set_default_password=True, \
                                        object_class=['top', 'person', 'organizationalPerson', 'user']):
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        if not dest_dn:
            try:
                self.add(dn=source_new_dn, object_class=object_class, attributes=source_attributes)
                if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                    logging.info('Пользователь DN: ' + source_new_dn + ' добавлен')
                else:
                    logging.error('Пользователь DN: ' + source_new_dn + ' не создан. Ошибка: ' + self.result['message'] )
                pass
            except LDAPException as error:
                logging.critical(error)
                pass
            if set_default_password and self.result['description'] == 'success':
                self.extend.microsoft.modify_password(source_new_dn, new_password=default_password)
                self.modify(source_new_dn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
                self.modify(source_new_dn, {'pwdLastSet': [('MODIFY_REPLACE', 0)]})
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info('Пароль \'' + default_password + '\' установлен для пользователя DN: ' + source_new_dn)
                pass
        else:
            logging.info('Пользователь DN: ' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])
            else:
                logging.error('Пользователь DN: ' + source_new_dn + ' Существует больше одного объекта с novellGUID: ' + source_attributes['novellGUID'])
            pass
        pass
    pass



    def add_group_record(self, source_new_dn: str, source_attributes: dict, dest_attributes: dict, object_class = ['top', 'group']):
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        if not dest_dn:
            self.add(dn=source_new_dn, object_class = object_class, attributes=source_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('Группа DN: ' + source_new_dn + ' добавлена')
            else:
                logging.error('Группа DN: ' + source_new_dn + ' не создана. Ошибка: ' + self.result['message'] )
            pass
        else:
            logging.info('Группа DN:' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])
            pass
        pass
    pass



    def add_users_to_group(self, members_dn: list, group_dn: str):
        source_user_list = [entry.lower() for entry in members_dn]
        dest_group_members=[entry.lower() for entry in self.search_records(filter ='(objectclass=group)',search_base=group_dn, attrubite_list=['member'])[0].member]
        ## Предварительно выполняем проверку состава групп между серверами
        if not (set(source_user_list) == set(dest_group_members)):
        # Eсли на целевом отличаются, то пользователей удаляем
            members_for_del = [element for element in dest_group_members if element not in source_user_list]
            if len(members_for_del) > 0:
                ad_remove_members_from_groups(connection=self, members_dn=members_for_del, groups_dn=group_dn, fix=True, raise_error=False)
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info('Из группы '+ group_dn  + ' удалены пользователи: ' + '\n'.join(members_for_del))
                else:
                    logging.error('При удалении из группы DN: ' + group_dn + ' ошибка: ' + self.result['message'] )
                pass
        # Добавляем пользоватлей в группу
            # Перед добавлением выполняется проверка, есть ли пользователи на целевом сервере
            dest_user_list = [entry.entry_dn.lower() for entry in self.search_records(filter ='(objectclass=Person)',search_base=self.server.get_split_fqdn())]
            common_users = set(source_user_list) & set(dest_user_list)
            not_on_dest_server = [element for element in source_user_list if element not in common_users]
            if len(not_on_dest_server) > 0:
                logging.warning("Для группы " + group_dn + " нет пользователей на целевом севере:\n{}".format('\n'.join(map(str, not_on_dest_server))))
            try:
                ad_add_members_to_groups(connection=self, members_dn=common_users, groups_dn=group_dn, fix=True, raise_error=False)
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info("Для группы " + group_dn + " обновлено/добавлено членство пользователей:\n{}".format('\n'.join(map(str, common_users))))
                elif self.result['description'] == 'success' and self.result['type'] == 'searchResDone':
                    pass
                else:
                    logging.error("При добавлении пользователей в группу: " + group_dn + " возникла ошибка: " + self.result['message'] )
                pass
            except LDAPInvalidDnError as error:
                logging.error(error)
                pass



    def delete_records(self, dn: str):
        self.delete(dn)
        if self.result['description'] == 'success' and self.result['type'] == 'delResponse':
            logging.info("Удален DN: " + dn)
        else:
            logging.error("При удалении DN: " + dn + " возникла ошибка: " + self.result['message'] )
    pass
    
pass

