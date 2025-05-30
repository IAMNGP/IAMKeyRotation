import json
import boto3
import os
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize clients
iam = boto3.client('iam')
secretsmanager = boto3.client('secretsmanager')

def lambda_handler(event, context):
    try:
        # Retrieve the semicolon-separated secret IDs from the environment variable
        secret_ids = os.getenv('SECRET_ID')
        
        if not secret_ids:
            raise ValueError("Environment variable 'SECRET_ID' is not set.")
        
        # Split and process each secret ID
        for secret_id in secret_ids.split(';'):
            secret_id = secret_id.strip()
            if not secret_id:
                continue
            
            logger.info(f"Processing secret: {secret_id}")
            
            # Retrieve the secret value from Secrets Manager
            get_secret = secretsmanager.get_secret_value(SecretId=secret_id)
            secret_details = json.loads(get_secret['SecretString'])
            username = secret_details.get('UserName')
            
            if not username:
                raise ValueError(f"Secret {secret_id} does not contain a valid 'UserName'.")
            
            logger.info(f"For user - {username}, Access & Secret keys will be inactivated.")
            
            # Extract key details from IAM
            key_response = iam.list_access_keys(UserName=username)
            
            # Existing Key Inactivation
            for key in key_response['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    iam.update_access_key(
                        AccessKeyId=key['AccessKeyId'],
                        Status='Inactive',
                        UserName=username
                    )
                    logger.info(f"Inactivated key: {key['AccessKeyId']} for user: {username}")
            
            # New Key Creation
            create_response = iam.create_access_key(UserName=username)
            new_access_key = create_response['AccessKey']
            logger.info(f"Created new access key for user: {username}")
            
            # Updating the secret value
            new_secret = {
                "UserName": new_access_key['UserName'],
                "AccessKeyId": new_access_key['AccessKeyId'],
                "SecretAccessKey": new_access_key['SecretAccessKey']
            }
            secretsmanager.update_secret(
                SecretId=secret_id,
                SecretString=json.dumps(new_secret)
            )
            logger.info(f"Updated secret: {secret_id} with new key details for user: {username}")
        
        return "Process of key rotation and secret update completed for all secrets."
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise e
