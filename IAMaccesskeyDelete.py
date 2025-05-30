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
            
            logger.info(f"For user - {username}, inactive Access & Secret keys will be deleted.")
            
            # Extract key details from IAM
            key_response = iam.list_access_keys(UserName=username)
            
            # Inactive Key Deletion
            for key in key_response['AccessKeyMetadata']:
                if key['Status'] == 'Inactive':
                    iam.delete_access_key(AccessKeyId=key['AccessKeyId'], UserName=username)
                    logger.info(f"Deleted inactive key: {key['AccessKeyId']} for user: {username}")
        
        return "Process of inactive key deletion completed for all users."
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise e
