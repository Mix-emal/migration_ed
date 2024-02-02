import json
from ldap3.utils.log import *
from connector import LDAP_Connector
from data import LDAP_Type


def __main__():


    with open('config.json', 'r', encoding='utf-8') as file:
        json_config = json.load(file)
        pass

    ad_connector = LDAP_Connector(fqdn=json_config['READ_DOMAIN_DC_FQDN'], ldap_manager=json_config['READ_DOMAIN_ADMIN_USERNAME'], ldap_password=json_config['READ_ADMIN_PASSWORD'], ldap_type=LDAP_Type.Edirectory)
    samba_connector = LDAP_Connector(fqdn=json_config['WRITE_DOMAIN_DC_FQDN'], ldap_manager=json_config['WRITE_DOMAIN_ADMIN_USERNAME'], ldap_password=json_config['WRITE_ADMIN_PASSWORD'], ldap_type=LDAP_Type.SambaDC)

    ad_ou_list = ad_connector.search_records(filter=json_config['LDAP_FILER_OU'], search_base=json_config['MIGRATION_DEFAULT_OU'], attrubite_list='cn')
    ad_groups_list = ad_connector.search_records(filter=json_config['LDAP_FILER_GROUP'], search_base=json_config['MIGRATION_DEFAULT_OU'], attrubite_list=json_config['MIGRATION_ATTRIBUTES_GROUP'])
    ad_user_list = ad_connector.search_records(filter=json_config['LDAP_FILTER_USER'], search_base=json_config['MIGRATION_DEFAULT_OU'], attrubite_list=json_config['MIGRATION_ATTRIBUTES_DICT'])
    index_list, new_ad_list = [], []
    #new_ad_list = []

    for ou in ad_ou_list:
        ou_dn = str(ou).split(' ')
        ou_dn = ou_dn[1]
        ou_dn = str(ou_dn).split(',')
        new_ou_dn = [i for i in ou_dn if i.find("o=")]
        new_ou_dn = ','.join(new_ou_dn)
        new_ou_dn += ',' + samba_connector.server.get_split_fqdn()
        new_ad_list.append(new_ou_dn)
        count = new_ou_dn.count("ou=")
        if count > 0:
            index_list.append(count)
        pass
    zip_list = list(zip(new_ad_list, index_list))
    res_list = sorted(zip_list, key = lambda val: val[1])
    new_ad_list, del_index = zip(*res_list)
    print(new_ad_list)

    for ou in new_ad_list:
        samba_connector.add_ou_record(ou)
    pass


    for group in ad_groups_list:
       # print(group)
        group_dn = str(group).split(' ')
        group_dn = group_dn[1]
        group_dn = str(group_dn).split(',')
        new_group_dn = [i for i in group_dn if i.find("o=")]
        new_group_dn = ','.join(new_group_dn)
        new_group_dn += ',' + samba_connector.server.get_split_fqdn()
#        print(new_group_dn)
        samba_connector.add_group_record(new_dn=new_group_dn, record_attributes={'cn': str(group['cn']), 'name': str(group['cn']), 'sAMAccountName': str(group['sAMAccountName'])})
#        group_dn = str(group['cn']).split(',')
#        new_group_dn = [i for i in group_dn if i.find("DC")]
#        new_group_dn = ','.join(new_group_dn)
#        new_group_dn += ',' + samba_connector.server.get_split_fqdn()
#        samba_connector.add_group_record(new_dn=new_group_dn, record_attributes={'cn': str(group['cn']), 'name': str(group['cn']), 'sAMAccountName': str(group['sAMAccountName'])})
    pass

    for user in ad_user_list:
        print(user['cn'])
        user_dn = str(user).split(' ')
        user_dn = user_dn[1]
        user_dn = str(user_dn).split(',')
        new_user_dn = [i for i in user_dn if i.find("o=")]
        new_user_dn = ','.join(new_user_dn)
        new_user_dn += ',' + samba_connector.server.get_split_fqdn()
        user_group = list(user['groupmembership'])
#        print(user_group)
        groups = []
        for group in user_group:
            group = str(group).split(',')
            new_group_dn = [i for i in group if i.find("o=")]
            new_group_dn = ','.join(new_group_dn)
            new_group_dn += ',' + samba_connector.server.get_split_fqdn()
            groups.append(new_group_dn)
            print(groups)
        pass

#        user_dn = str(user['distinguishedName']).split(',')
#        new_user_dn = [i for i in user_dn if i.find("DC")]
#        new_user_dn = ','.join(new_user_dn)
#        new_user_dn += ',' + samba_connector.server.get_split_fqdn()
#        groups = []
#        user_group = list(user['memberOf'])
#        for group in user_group:
#            group = str(group).split(',')
#            new_group_dn = [i for i in group if i.find("DC")]
#            new_group_dn = ','.join(new_group_dn)
#            new_group_dn += ',' + samba_connector.server.get_split_fqdn()
#            groups.append(new_group_dn)
#            pass

#        user_attrs = {
#            'l': str(user['l']),
#            'cn':  str(user['cn']),
#            'co': str(user['co']), 
#            'company': str(user['company']),
#            'department': str(user['department']),
#            'displayName': str(user['displayName']),
#            'division': str(user['division']),
#            'employeeID': str(user['employeeID']),
#            'givenName': str(user['givenName']),
#            'initials': str(user['initials']),
#            'ipPhone': str(user['ipPhone']),
#            'name': str(user['name']),
#            'physicalDeliveryOfficeName': str(user['physicalDeliveryOfficeName']),
#            'postalCode': str(user['postalCode']),
#            'samAccountName': str(user['cn']),
#            'sn': str(user['sn']),
#            'st': str(user['st']),
#            'streetAddress': str(user['streetAddress']),
#            'telephoneNumber': str(user['telephoneNumber']),
#            'title': str(user['title'])
#        }
        user_attrs = {
            'l': str(user['l']),
            'cn':  str(user['cn']),
#            'co': str(user['co']), 
#            'company': str(user['company']),
#            'department': str(user['department']),
            'displayName': str(user['fullname']),
#            'division': str(user['division']),
#            'employeeID': str(user['employeeID']),
            'givenName': str(user['givenName']),
            'initials': str(user['initials']),
#            'ipPhone': str(user['ipPhone']),
            'name': str(user['fullname']),
#            'physicalDeliveryOfficeName': str(user['physicalDeliveryOfficeName']),
#            'postalCode': str(user['postalCode']),
            'samAccountName': str(user['sAMAccountName']),
            'sn': str(user['sn']),
#            'st': str(user['st']),
#            'streetAddress': str(user['streetAddress']),
            'telephoneNumber': str(user['telephoneNumber']),
            'title': str(user['title']),
            'mail': str(user['mail']),
        }
        samba_connector.add_user_record(new_dn=new_user_dn, set_default_password=True, add_into_groups=True, default_password=json_config['DEFAULT_USER_MIGRATION_PASSWORD'], group_list=groups, record_attributes=user_attrs)
    pass

__main__()

