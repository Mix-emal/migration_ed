from ldap3 import Connection
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPInvalidDnError
from data import Server_Data, LDAP_Type
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from logger import logging
from deepdiff import DeepDiff
#from dictdiffer import diff, patch, swap, revert
from dictionary_diff import diff

class DictionaryCompare:
    @staticmethod
    def get_common_key_value_pairs(first_dictionary, second_dictionary):
        result_dictionary = {}
        for key in first_dictionary.keys():
            # if key in second_dictionary.keys():
            if first_dictionary[key] == second_dictionary[key]:
                result_dictionary[key] = first_dictionary[key]

        return result_dictionary
    
class UncasedDict(dict):                                                        
    def __getitem__(self, key):                                                 
        if isinstance(key, str):                                                
            key = key.lower()                                                   
        return super().__getitem__(key)                                         
                                                                                
    def __setitem__(self, key, value):                                          
        if isinstance(key, str):                                                
            key = key.lower()                                                   
        return super().__setitem__(key, value)     
    
# class CaseInsensitiveDict(dict):
#     def __setitem__(self, key, value):
#         super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

#     def __getitem__(self, key):
#         return super(CaseInsensitiveDict, self).__getitem__(key.lower())
    


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

    def __is_record_exist(self, search_filer: str, attr: list):
        search = '(novellGUID={})'.format(search_filer)
        records = self.search_records(filter=search, search_base=self.server.get_split_fqdn(), attrubite_list=attr)
        return records
        # return True if records else False
    

    def compare_records(self, source_dn: str, source_attr: dict, dest_object):
        source_dict = UncasedDict()
        keylower_source_attr = {k.lower():v for k,v in source_attr.items()}
        #print(keylower_source_attr)
        source_dict[source_dn] = source_attr
        s = UncasedDict(source_attr)
        
        dest_dict = UncasedDict()
        # print(dest_object.entry_dn)
        dest_attr_dict = UncasedDict()
        for entry in dest_object.entry_attributes:
            dest_attr_dict[entry] = str(dest_object[entry])
        dest_dict[dest_object.entry_dn] = dest_attr_dict
        d = UncasedDict(dest_attr_dict)
        print('****************source_dict***********')
        print(source_dict)
        print('******************dest_dict***********')
        print(dest_dict)
        print('**************************************')
        print(source_dict)
        # results = DictionaryCompare.get_common_key_value_pairs(s, d)

        # # Print out the results
        # print(results)
        # for key, value in results.items():
        #     print(key)
        #     print(value)
        diff_ou = diff(source_dict,dest_dict)
        print(diff_ou)
    




    def add_ou_record(self, new_dn: str, record_attributes: dict, object_class = ['organizationalUnit']):
        # print(new_dn, ' + ', object_class)
        dest_dn = self.__is_record_exist(record_attributes['novellGUID'],attr=list(record_attributes))
        if not dest_dn:
            self.add(dn=new_dn, object_class = object_class, attributes=record_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('OU DN: ' + new_dn + ' добавлен')
            else:
                logging.error('OU DN: ' + new_dn + ' не создан. Ошибка: ' + self.result['message'] )
            pass
        else:
            if len(dest_dn) == 1:
                self.compare_records(source_dn = new_dn, source_attr = record_attributes, dest_object = dest_dn[0])
            else:
                logging.error('OU DN: ' + new_dn + ' Существует больше одного обэекта с novellGUID: ' + record_attributes['novellGUID'])
            logging.info('OU DN: ' + new_dn + ' уже существует')
        pass


    def add_user_record(self, new_dn: str, default_password: str, record_attributes: dict, set_default_password=True, object_class=['top', 'person', 'organizationalPerson', 'user']):
        dest_dn = self.__is_record_exist(record_attributes['novellGUID'],attr=list(record_attributes))
        if not dest_dn:
            try:
                self.add(dn=new_dn, object_class=object_class, attributes=record_attributes)
                if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                    logging.info('Пользователь DN: ' + new_dn + ' добавлен')
                else:
                    logging.error('Пользователь DN: ' + new_dn + ' не создан. Ошибка: ' + self.result['message'] )
                pass
            except LDAPException as error:
                logging.critical(error)
                pass
            if set_default_password and self.result['description'] == 'success':
                self.extend.microsoft.modify_password(new_dn, new_password=default_password)
                self.modify(new_dn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
                self.modify(new_dn, {'pwdLastSet': [('MODIFY_REPLACE', 0)]})
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info('Пароль \'' + default_password + '\' установлен для пользователя DN: ' + new_dn)
                pass
            # if add_into_groups:
            #     for group in group_list:
            #         ad_add_members_to_groups(connection=self, groups_dn=group, members_dn=new_dn)
            #         logging.info('User with DN ' + new_dn + ' was add into group ' + group)
            #     pass
        else:
            if len(dest_dn) == 1:
                self.compare_records(source_dn = new_dn, source_attr = record_attributes, dest_object = dest_dn[0])
            else:
                logging.error('Пользователь DN: ' + new_dn + ' Существует больше одного обэекта с novellGUID: ' + record_attributes['novellGUID'])
            logging.info('Пользователь DN: ' + new_dn + ' уже существует')
            pass
        pass


    def add_group_record(self, new_dn: str, record_attributes: dict, object_class = ['top', 'group']):
        if not self.__is_record_exist(record_attributes['novellGUID']):
            self.add(dn=new_dn, object_class = object_class, attributes=record_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('Группа DN: ' + new_dn + ' добавлена')
            else:
                logging.error('Группа DN: ' + new_dn + ' не создана. Ошибка: ' + self.result['message'] )
            pass
        else:
            logging.info('Группа DN:' + new_dn + ' уже существует')
            pass
        pass
    pass


    def add_users_to_group(self, members_dn: list, group_dn: str):
        # Предварительно выполняем проверку какие пользователи есть на целевом сервере
        source_user_list = [entry.lower() for entry in members_dn]
        dest_user_list = [entry.entry_dn.lower() for entry in self.search_records(filter ='(objectclass=Person)',search_base=self.server.get_split_fqdn())]
        common_users = set(source_user_list) & set(dest_user_list)
        not_on_dest_server = [element for element in source_user_list if element not in common_users]
        if len(not_on_dest_server) > 0:
            logging.warning("Для группы " + group_dn + " нет пользователей на целевом севере:\n\t{}".format('\n'.join(map(str, not_on_dest_server))))
        try:
            ad_add_members_to_groups(connection=self, members_dn=common_users, groups_dn=group_dn, fix=True, raise_error=False)
            if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                logging.info("Для группы " + group_dn + " обновлено/добавлено членство пользователей:\n\t{}".format('\n'.join(map(str, common_users))))
            elif self.result['description'] == 'success' and self.result['type'] == 'searchResDone':
                pass
            else:
                logging.error(self.result['message'] )
            pass
        except LDAPInvalidDnError as error:
            logging.error(error)
            pass
    pass
    

