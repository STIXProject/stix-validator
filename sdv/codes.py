# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
'''
This module defines exit status codes used by bundled scripts.
'''

#: Execution finished successfully. All STIX documents were valid for all user-
#: specified validation scenarios.
EXIT_SUCCESS                = 0x0

#: Execution finished with fatal system error. Some unhandled system exception
#: was raised during execution.
EXIT_FAILURE                = 0x1

#: Execution finished with at least one input document found to be schema-
#: invalid.
EXIT_SCHEMA_INVALID         = 0x2

#: Execution finished with at least one input document found to be profile
#: invalid.
EXIT_PROFILE_INVALID        = 0x4

#: Execution finished with at least one input document found to be best practice
#: invalid.
EXIT_BEST_PRACTICE_INVALID  = 0x8

#: An error occurred while validating an instance document. This can be caused
#: by malformed input documents or file names that do not resolve to actual
#: files.
EXIT_VALIDATION_ERROR       = 0x10