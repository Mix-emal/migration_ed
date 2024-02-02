import logging
from ldap3.utils.log import *


logging.basicConfig(filename='migration.log', level=logging.CRITICAL)
set_library_log_activation_level(logging.CRITICAL)
set_library_log_detail_level(EXTENDED)
set_library_log_hide_sensitive_data(False)

