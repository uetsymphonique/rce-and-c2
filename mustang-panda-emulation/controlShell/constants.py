# REST API constants (mirrors evalsC2client.py)
API_RESP_TYPE_KEY    = "type"
API_RESP_STATUS_KEY  = "status"
API_RESP_DATA_KEY    = "data"
API_RESP_STATUS_OK   = 0

RESP_TYPE_CTRL         = 0
RESP_TYPE_VERSION      = 1
RESP_TYPE_CONFIG       = 2
RESP_TYPE_SESSIONS     = 3
RESP_TYPE_TASK_CMD     = 4
RESP_TYPE_TASK_OUTPUT  = 5
RESP_TYPE_TASK_INFO    = 6

TASK_STATUS_KEY    = "taskStatus"
TASK_GUID_KEY      = "guid"
TASK_COMMAND_KEY   = "command"
TASK_OUTPUT_KEY    = "taskOutput"
TASK_STATUS_NEW       = 0
TASK_STATUS_PENDING   = 1
TASK_STATUS_FINISHED  = 2
TASK_STATUS_DISCARDED = 3

# ToneShell packet type IDs
TS_FILE_DOWNLOAD = 3   # server -> implant (push file to implant)
TS_EXEC          = 5   # execute shell command on implant
TS_FILE_UPLOAD   = 7   # implant -> server (pull file from implant)
TS_TERMINATE     = 255 # self-destruct
