from ldap3 import Connection
from ldap3.core.exceptions import LDAPException, LDAPBindError
from data import Server_Data, LDAP_Type
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from logger import logging


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


    def __is_record_exist(self, dn: str):
        records = self.search_records(search_base=self.server.get_split_fqdn() ,filter='(objectClass=*)')
        return True if dn in records else False   

    
    def add_user_record(self, new_dn: str, default_password: str, record_attributes: dict, group_list: list, set_default_password=True, add_into_groups=True, object_class=['top', 'person', 'organizationalPerson', 'user']):
        if not self.__is_record_exist(new_dn):
            try:
                self.add(dn=new_dn, object_class=object_class, attributes=record_attributes)
                pass
            except LDAPException as error:
                logging.critical(error)
                pass
            logging.critical('User with DN ' + new_dn + 'was add')
            if set_default_password:
                self.extend.microsoft.modify_password(new_dn, new_password=default_password)
                self.modify(new_dn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
                self.modify(new_dn, {'pwdLastSet': [('MODIFY_REPLACE', 0)]})
                logging.critical('Password ' + default_password + ' was set to User with DN ' + new_dn)
                pass
            if add_into_groups:
                for group in group_list:
                    ad_add_members_to_groups(connection=self, groups_dn=group, members_dn=new_dn)
                    logging.critical('User with DN ' + new_dn + ' was add into group ' + group)
                pass
        else:
            logging.critical('User with DN ' + new_dn + 'was already add')
            pass
        pass


    def add_ou_record(self, new_dn: str, object_class = ['organizationalUnit']):
        print(new_dn, ' + ', object_class)
        if not self.__is_record_exist(new_dn):
            self.add(new_dn, object_class)
            logging.critical('OU with DN ' + new_dn + ' add')
            pass
        else:
             logging.critical('OU with DN ' + new_dn + ' was already add')
        pass


    def add_group_record(self, new_dn: str, record_attributes: dict, object_class = ['top', 'group']):
        if not self.__is_record_exist(new_dn):
            self.add(dn=new_dn, object_class = object_class, attributes=record_attributes)
            logging.critical('Group with DN ' + new_dn + ' add')
            pass
        else:
            logging.critical('Group with DN ' + new_dn + ' was already add')
            pass
        pass
    pass

