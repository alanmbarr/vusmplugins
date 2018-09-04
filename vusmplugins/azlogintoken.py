from azure.cli.core import get_default_cli
from six import StringIO
import json
io = StringIO()
get_default_cli().invoke(['account', 'get-access-token'],out_file=io)
result = io.getvalue()

tokenResponse = json.loads(result)
token = tokenResponse.get('accessToken')
subscription = tokenResponse.get('subscription')

vuconfig = {'VeteransUnited':{'token':token,'subscription':subscription}}
print(json.dumps(vuconfig))