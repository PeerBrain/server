import os
import secrets

from dotenv import load_dotenv

def generate_url_safe_secret(length=32):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    url_safe_secret = ''.join(secrets.choice(alphabet) for _ in range(length))
    return url_safe_secret


def load_settings_or_prompt():
    env_file = ".env"

    if not os.path.exists(env_file):
        # Prompt the user for input
        fast_api_secret = generate_url_safe_secret(48)
        
        print("PEERBRAIN SERVER INITIAL CONFIG \n\n")
        
        print('No .env file could be found. Please enter all the necessary info below: \n\n')
        
        server_url = input("Enter the url for your Peerbrain Server: \n")
        
        database_uri = input("Enter your database URI: \n")
        
        sym_key_api_url = input("Enter the URL of your Symmetric Key Server: \n")
        sym_key_gen_api_key = input("Enter your Symmetric Key API key from the init endpoint: \n")
        sym_key_micro_key = input("Enter your Symmetric Key Micro Key: \n")
        
        email_password = input("Enter the password for your email: \n")
        email_sender = input("Enter your email address: \n")
        email_username = input("Enter your username for the email address: \n")
        
        reset_password_route = generate_url_safe_secret()
                
        # Write the values to the .env file
        with open(env_file, "w") as f:
            f.write(f"#Fast API Secret key ==> To be randomly generated in the future\n")
            f.write(f"SECRET_KEY={fast_api_secret}\n\n")
            
            f.write(f"#Peerbrain application server url\n")
            f.write(f"SERVER_URL={server_url}\n\n")
            
            f.write(f"#Database URI\n")
            f.write(f"DATABASE_URI={database_uri}\n\n")
            
            f.write(f"#Symmetric Key Server API Credentials\n")
            f.write(f"SYM_KEY_API_URL={sym_key_api_url}\n")
            f.write(f"SYM_KEY_API_KEY={sym_key_gen_api_key}\n")
            f.write(f"SYM_KEY_X_API_KEY={sym_key_micro_key}\n\n")
            
            f.write(f"#Email Credentials\n")
            f.write(f"EMAIL_PASS={email_password}\n")
            f.write(f"EMAIL_SENDER={email_sender}\n")
            f.write(f"EMAIL_USERNAME={email_username}\\nn")
            
            f.write(f"#Reset Password route")            
            f.write(f"RESET_PASSWORD_ROUTE={reset_password_route}\n")

    # Load the environment variables from the .env file
    load_dotenv(env_file)