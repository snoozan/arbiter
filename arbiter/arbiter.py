import boto3
import logging
import sys
import os

from flask import Flask
from flask import json, request
app = Flask(__name__)

logger = logging.getLogger()
logger.setLevel(logging.ERROR)

errlog = logging.StreamHandler(sys.stdout) 
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
errlog.setFormatter(formatter)
logger.addHandler(errlog)

access_key_id = os.environ['ACCESS_ID']
secret_access_key = os.environ['SECRET_KEY'] 

@app.route('/eip', methods=['POST'])
def process_heartbeat():
    if request.method == 'POST':
        try :
            data = json.loads(request.data)
        except:
            logger.error("Malformed request data {}".format(request.data))

        client = boto3.client('ec2',
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name='us-east-2'
        )

        try:
            old = data['old']
            new = data['new']
        except:
            logger.error("Data does not contain correctly formatted \
                    json".format(request.data))

        # disassociate address from old master
        response = client.disassociate_address(
                PublicIp=old,
                DryRun=True
        )
        if (response.status_code != 200):
            logger.error("Disassociation failed. {}".format(response.exceptions))
            return 'Failed request'

        response = client.associate_address(
                PublicIp=new,
                DryRun=True
        )

        if (response.status_code != 200):
            logger.error("Association failed. {}".format(response.exceptions))
            return 'Failed request'
        return 'Successfully elected new master {}'.format(new)
    else:
        return 'Malformed request'
    return 'Non-post request'

if __name__ == "__main__":
    app.run(host='0.0.0.0')
