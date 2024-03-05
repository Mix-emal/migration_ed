from ldap3 import Connection
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPInvalidDnError
from data import Server_Data, LDAP_Type
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
import re
from logger import logging


## Класс словаря, который является регистронезависимым - ключи в нем обрабатываются без учета регистра.
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

    def __init__(self, fqdn: str, ldap_type: LDAP_Type, ldap_manager: str, ldap_password: str, \
                 source_root_dn: str, dest_root_dn: str):
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
        self.source_root_dn = source_root_dn
        self.dest_root_dn = dest_root_dn

        try:
            super().__init__(server=self.server_data, user=self.__ldap_manager, password=self.__ldap_password)
            super().bind()
            pass
        except LDAPBindError as error:
            logging.critical(error)

## Метод для сравнения атрибутов. Принимает два словаря, source_attr_dict и dest_attr_dict,
# и сравнивает их значения. Возвращает новый словарь result_dictionary, содержащий ключи, которые были изменены, 
# а также соответствующие изменения.
    @staticmethod
    def __get_changed_attr(source_attr_dict: dict, dest_attr_dict: dict):
        result_dictionary = {}
        for key in dest_attr_dict.keys():
            if key in source_attr_dict:
                if source_attr_dict[key] != dest_attr_dict[key]:
                    result_dictionary[key] = ['MODIFY_REPLACE', (source_attr_dict[key])]
            else:
                if dest_attr_dict[key] != '[]':
                    result_dictionary[key] = ['MODIFY_REPLACE', list('')]
        return result_dictionary
    
## Метод для преобразования регистра. Применяется для стандартизации регистра в строках DN
    @staticmethod
    def __lower_case_cn_ou_dc(input_string: str):
        input_string = input_string.replace('CN=', 'cn=')
        input_string = input_string.replace('OU=', 'ou=')
        input_string = input_string.replace('DC=', 'dc=')
        return input_string

## Метод выполняющий поиск записей на основе аттрибута novellGUID. По умолчанию возвращает аттрибут distinguishedName
    def __is_record_exist(self, search_filer: str, attr=['distinguishedName']):
        search = '(novellGUID={})'.format(search_filer)
        records = self.search_records(filter=search, search_base=self.dest_root_dn, attribute_list=attr)
        return records

## Метод выполняющий поиск записей на основе заданного фильтра. По умолчанию возвращает аттрибут distinguishedName
    def search_records(self, filter: str, search_base: str, attribute_list=['distinguishedName']):
        self.search(search_base=search_base, search_filter=filter, attributes=attribute_list)
        return self.entries

## Метод для конвертации DN в формат целевого сервера (замена rootDN)
    def convert_dn(self, dn: str):
        # Регистронезависимая замена
        compiled = re.compile(re.escape(self.source_root_dn), re.IGNORECASE)
        dn_new = compiled.sub(self.dest_root_dn, dn)
        # dn = dn.replace(self.source_root_dn.lower(), self.dest_root_dn)
        return dn_new

## Метод предназначен для сравнения и обновления записей в LDAP
    def compare_records(self, source_dn: str, source_attr: dict, dest_object):
    # Подготовка данных для сравнения: DN и атрибуты: Извлекаются и подготавливаются данные для сравнения, 
    # включая разделение DN на составляющие, приведение к нижнему регистру и формирование словаря атрибутов для целевого объекта.
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
        # Если Organizational Units (OU) записи не совпадают, производится перемещение записи в другой контейнер.
        if dest_cn == source_cn and source_container != dest_container:
            self.modify_dn(dest_object.entry_dn, dest_cn, new_superior=source_container)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' перемещен в контейнер ' + source_container)
            else:
                logging.error('DN: ' + dest_object.entry_dn + '. Ошибка перемещения: ' + self.result['message'] )
        # Если Common Name (CN) записи на целевом сервере не совпадает с источником, производится переименование записи.
        elif dest_cn != source_cn and source_container == dest_container:
            self.modify_dn(','.join([dest_cn, dest_container]), source_cn)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' переименован в ' + source_cn)
            else:
                logging.error('DN: ' + dest_object.entry_dn + ' при переименовании произошла ошибка: ' + self.result['message'] )
        # Если и CN, и OU не совпадают, выполняются и переименование, и перемещение.
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
        # Вызывается функция __get_changed_attr, чтобы определить измененные атрибуты между источником и целевым объектом.
        compare_attributes = self.__get_changed_attr(source_attr, dest_attr_dict)
        # Если есть изменения, вызывается функция modify для обновления атрибутов на целевом сервере.
        if compare_attributes:
            self.modify(source_dn, compare_attributes)
            if self.result['description'] == 'success':
                logging.info('DN: ' + dest_object.entry_dn + ' обновлены атрибуты: ' + ' ,'.join(list(compare_attributes.keys())))
            else:
                logging.error('DN: ' + dest_object.entry_dn + ' ошибка при обновлении атрибутов ' + ' ,'.join(list(compare_attributes.keys())) + ': ' + self.result['message'] )

## Метод для добавления записи (organizationalUnit) в LDAP-каталог. 
    def add_ou_record(self, source_new_dn: str, \
                      source_attributes: dict, \
                        dest_attributes: list, \
                            object_class = ['organizationalUnit']):
        # Проверка существования записи
        # Вызывается метод __is_record_exist для проверки существования записи с указанным novellGUID и другими атрибутами.
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        # Если запись не существует, она добавляется. 
        if not dest_dn:
            self.add(dn=source_new_dn, object_class = object_class, attributes=source_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('OU DN: ' + source_new_dn + ' добавлен')
            else:
                logging.error('OU DN: ' + source_new_dn + ' не создан. Ошибка: ' + self.result['message'] )
        # В противном случае производится логирование и вызывается метод compare_records (сравнение)
        else:
            logging.info('OU DN: ' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])
            else:
                logging.error('OU DN: ' + source_new_dn + ' Существует больше одного объекта с novellGUID: ' + source_attributes['novellGUID'])


## Метод для добавления учетной записи в LDAP-каталог. 
    def add_user_record(self, source_new_dn: str, \
                        default_password: str, \
                            source_attributes: dict, \
                                dest_attributes: list, \
                                    set_default_password=True, \
                                        disable_user=True, \
                                            object_class=['top', 'person', 'organizationalPerson', 'user']):
        # Предварительная проверка, существует ли пользователь на целевом сервре
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        # Если не существует, то пользователь создается
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
            # Задание пароля для пользователя
            if set_default_password and self.result['description'] == 'success':
                self.extend.microsoft.modify_password(source_new_dn, new_password=default_password)
                # По умолчанию (определяется в конфигурации) пользователь создается неактивным (userAccountControl = 514)
                if disable_user.lower() == 'true':
                    self.modify(source_new_dn, {'userAccountControl': [('MODIFY_REPLACE', 514)]})
                else:
                    self.modify(source_new_dn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
                # Установка флага для смены пароля при первом входе
                self.modify(source_new_dn, {'pwdLastSet': [('MODIFY_REPLACE', 0)]})
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info('Пароль \'' + default_password + '\' установлен для пользователя DN: ' + source_new_dn)
                pass
        # В противном случае производится логирование и вызывается метод compare_records (сравнение)
        else:
            logging.info('Пользователь DN: ' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])
            else:
                logging.error('Пользователь DN: ' + source_new_dn + ' Существует больше одного объекта с novellGUID: ' + source_attributes['novellGUID'])

## Метод для добавления группы в LDAP-каталог. 
    def add_group_record(self, source_new_dn: str, source_attributes: dict, dest_attributes: dict, object_class = ['top', 'group']):
        # Проверка существования записи
        # Вызывается метод __is_record_exist для проверки существования записи с указанным novellGUID и другими атрибутами.
        dest_dn = self.__is_record_exist(source_attributes['novellGUID'],attr=list(dest_attributes))
        # Если не существует, то группа создается
        if not dest_dn:
            self.add(dn=source_new_dn, object_class = object_class, attributes=source_attributes)
            if self.result['description'] == 'success' and self.result['type'] == 'addResponse':
                logging.info('Группа DN: ' + source_new_dn + ' добавлена')
            else:
                logging.error('Группа DN: ' + source_new_dn + ' не создана. Ошибка: ' + self.result['message'] )
        # В противном случае производится логирование и вызывается метод compare_records (сравнение)
        else:
            logging.info('Группа DN:' + source_new_dn + ' уже существует')
            if len(dest_dn) == 1:
                self.compare_records(source_dn = source_new_dn, source_attr = source_attributes, dest_object = dest_dn[0])

## Метод для синхронизации членства в группе между двумя серверами LDAP
    def update_user_membership(self, source_group_members: list, group_dn: str):
        # Получение текущих членов группы на целевом сервере:
        # Используется метод search_records для поиска записи группы и получения ее членов.
        # Результат сохраняется в множество dest_group_members.
        dest_group_members = set(entry.lower() for entry in self.search_records(filter='(objectclass=group)', \
                                                                                search_base=group_dn,\
                                                                                      attribute_list=['member'])[0].member)
        # Проверка различий между членами групп на источнике и целевом
        # Сравниваются списки членов группы на источнике (source_group_members) и на целевом сервере (dest_group_members).
        # Если есть различия, выполняются дополнительные шаги для обновления состава группы на целевом сервере
        if source_group_members != dest_group_members:
            # Удаление лишних пользователей из группы на целевом сервере
            # Вычисляются пользователи, которые есть в группе на целевом сервере, но отсутствуют в группе на источнике.
            members_for_del = dest_group_members.difference(source_group_members)
            # Если такие пользователи есть, они удаляются из группы
            if members_for_del:
                ad_remove_members_from_groups(connection=self,\
                                               members_dn=members_for_del, \
                                                groups_dn=group_dn, \
                                                    fix=True, raise_error=False)
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info(f'Из группы {group_dn} удалены пользователи: {members_for_del}')
                else:
                    logging.error(f'При удалении из группы DN: {group_dn} ошибка: {self.result["message"]}')
            # Добавление новых пользователей в группу:
            # Вызывается метод ad_add_members_to_groups для добавления пользователей в группу.
            try:
                ad_add_members_to_groups(connection=self, members_dn=source_group_members,\
                                          groups_dn=group_dn, fix=True, raise_error=False)
                if self.result['description'] == 'success' and self.result['type'] == 'modifyResponse':
                    logging.info(f'Для группы {group_dn} обновлено/добавлено членство пользователей: {source_group_members}')
                elif self.result['description'] == 'success' and self.result['type'] == 'searchResDone':
                    pass
                else:
                    logging.error(f'При добавлении пользователей в группу: {group_dn} возникла ошибка: {self.result["message"]}')
            except LDAPInvalidDnError as error:
                logging.error(error)

## Метод для удаления записей (объектов) из LDAP-каталога.
#  В качестве входных данных получает словарь с идентификаторами объектов (атрибут NovellGUID)
    def delete_records(self, records: dict):
        # Итерация по переданным записям
        for record in records:
            # Получение DN (Distinguished Name) записи:
            # Вызывается метод __is_record_exist для поиска записи в LDAP-каталоге и получения ее DN.
            dn = self.__is_record_exist(record)[0].entry_dn
            # Удаление записи: Вызывается метод delete с переданным DN для удаления записи
            self.delete(dn)
            if self.result['description'] == 'success' and self.result['type'] == 'delResponse':
                logging.info("Удален DN: " + dn)
            else:
                logging.error("При удалении DN: " + dn + " возникла ошибка: " + self.result['message'] )
    pass
    
pass

