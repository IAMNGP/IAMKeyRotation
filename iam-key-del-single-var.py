import json
import boto3
import os

# Initialize clients
iam = boto3.client('iam')
secretsmanager = boto3.client('secretsmanager')

def lambda_handler(event, context):
    try:
        # Retrieve the single secret value from the environment variable
        secret_id = os.getenv('SECRET_ID')  # Replace 'SECRET_ID' with the name of your environment variable
        
        if not secret_id:
            raise ValueError("Environment variable 'SECRET_ID' is not set.")
        
        # Retrieve the secret value from Secrets Manager
        get_secret = secretsmanager.get_secret_value(SecretId=secret_id)
        secret_details = json.loads(get_secret['SecretString'])
        
        print(f"For user - {secret_details['UserName']}, inactive Access & Secret keys will be deleted.")
        
        # Extract key details from IAM
        key_response = iam.list_access_keys(UserName=secret_details['UserName'])
        
        # Inactive Key Deletion
        for key in key_response['AccessKeyMetadata']:
            if key['Status'] == 'Inactive':
                iam.delete_access_key(AccessKeyId=key['AccessKeyId'], UserName=key['UserName'])
                print(f"An inactive key - {key['AccessKeyId']} - of user {key['UserName']} has been deleted.")
        
        return "Process of inactive key deletion completed successfully."
    
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e
