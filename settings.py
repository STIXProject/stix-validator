# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os

SDV_ROOT = os.path.dirname(os.path.realpath(__file__))
SCHEMAS_ROOT = os.path.join(SDV_ROOT, "schemas")

SCHEMAS = {'1.1.1': os.path.join(SCHEMAS_ROOT, 'stix_1.1.1'),
           '1.1': os.path.join(SCHEMAS_ROOT, 'stix_1.1'),
           '1.0.1': os.path.join(SCHEMAS_ROOT, 'stix_1.0.1'),
           '1.0': os.path.join(SCHEMAS_ROOT, 'stix_1.0')}
