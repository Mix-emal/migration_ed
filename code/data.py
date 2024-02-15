from enum import Enum
from ldap3 import Server, Tls
import ssl
import json


class LDAP_Type (Enum):
    """
    A class to represent a LDAP types.
    ActiveDirectory
    SambaDC
    FreeIPA
    """

    ActiveDirectory = 0
    SambaDC = 1
    FreeIPA = 2
    Edirectory = 3
    pass



class Server_Data (Server):
    """
    A class to represent data for ldap server.

    Attributes
    ----------
    fqdn : str
        Fully Qualified Domain Name of the ldap server
    ldap_type : LDAP_Type
        LDAP type of the server
    ca_cert_path: str
        Path to CA certificate file

    Methods
    -------
    get_split_fqdn():
        Return server FQDN into, example dc01.croc.demo -> "DC=croc, DC=demo"
    """

    def __init__(self, fqdn: str, ldap_type: LDAP_Type, ca_certs_path='/var/lib/samba/private/tls/ca.pem'):
        """
        Init attributes for creating Server Object

        Parameters
        ----------
            fqdn : str
                Fully Qualified Domain Name of the ldap server
             ldap_type : LDAP_Type
                LDAP type of the server
            ca_cert_path: str, optional
                Path to CA certificate file (default is /etc/pki/ca-trust/source/anchors/ca.pem)
        
        Returns
        -------
        Server Object
        """

        self.__fqdn = fqdn
        self.__ldap_type = ldap_type
        self.__ca_cert_path = ca_certs_path

        # Samba DC work only with TLS, need CA Certificate path
    
        if ldap_type == LDAP_Type.SambaDC:

            # Init TLS object for SambaDC server, no validate it
            tls = Tls(validate=ssl.CERT_NONE, 
                      ca_certs_path=self.__ca_cert_path)
            super().__init__(self.__fqdn, use_ssl=True, tls=tls)
            pass
        elif ldap_type == LDAP_Type.Edirectory:
            tls = Tls(version=ssl.PROTOCOL_TLSv1, validate = ssl.CERT_NONE, ca_certs_file='Novell.pem')
            super().__init__(self.__fqdn, use_ssl=True, tls=tls)
            pass
        else:
            # Init FreeIPA, AD Server
            super().__init__(self.__fqdn)
            pass
        pass


    def get_split_fqdn(self):
        """
        Return server FQDN into, example dc01.croc.demo -> "DC=croc, DC=demo"

        Returns
        -------
        FQDN : str
        """
        
        ldap_address = ['dc=' + dc for dc in self.__fqdn.split('.')]
        ldap_address.pop(0)
        return ','.join(ldap_address)
    
    pass
