import asyncio
import getpass
import re
import datetime
import logging
from scrapli.logging import enable_basic_logging
from pathlib import Path
from scrapli import AsyncScrapli
from scrapli.exceptions import ScrapliAuthenticationFailed
from scrapli.exceptions import ScrapliTimeout
from scrapli.exceptions import ScrapliException
from asyncio import Semaphore

enable_basic_logging(file=True, level="debug")

# Set the number of concurrent workers
num_workers = 20  # Adjust this value based on your needs
worker_semaphore = Semaphore(num_workers)
# Define an asynchronous function to fetch and save the running configuration of a device
async def fetch_config(ip, username, password):
    async with worker_semaphore:
        device = {
            'host': ip,
            'auth_username': username,
            'auth_password': password,
            'auth_strict_key': False,
            'transport': 'asyncssh',
            'platform': 'cisco_iosxe',
            'transport_options': {
                'asyncssh': {
                    'encryption_algs': 'aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com',
                    'kex_algs': 'diffie-hellman-group1-sha1,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1',
                }
            },
        }
        try:
            async with AsyncScrapli(**device) as connection:
                output = await connection.send_command('show running-config')
                print(output.result)

                hostname = re.search(r'hostname (.+)', output.result)
                if hostname:
                    hostname = hostname.group(1)
                else:
                    hostname = 'unknown_hostname'

                backup_dir = Path('/home/backups/cisco/')
                backup_dir.mkdir(parents=True, exist_ok=True)

                current_date = datetime.datetime.now().strftime('%Y-%m-%d')
                file_name = f"{current_date}_{hostname}.txt"
                file_path = backup_dir / file_name

                with file_path.open('w') as f:
                    f.write(output.result)

                print(f"Saved running-config to: {file_path}")

        except ScrapliAuthenticationFailed:
            print(f"Authentication failed for device: {device['host']} ({device.get('hostname', 'N/A')})")
        except ScrapliTimeout:
            print(f"Timeout occurred while connecting to device: {device['host']} ({device.get('hostname', 'N/A')})")
        except ScrapliException as e:
            print(f"Error occurred while connecting to device: {device['host']} ({device.get('hostname', 'N/A')}). Error: {str(e)}")
        except OSError as e:
            print(f"Error occurred while connecting to device: {device['host']} ({device.get('hostname', 'N/A')}). Error: {str(e)}")
# Main asynchronous function
async def main():
        # Add your IP addresses here
    ips = [
        '10.1.1.1',
        '10.1.2.3'
    ]

    # Get the username and password
    username = 'admin'
    password = getpass.getpass("Enter password: ")

    # Create a list of tasks to fetch configurations for all devices
    tasks = [fetch_config(ip, username, password) for ip in ips]
    # Execute all tasks concurrently
    await asyncio.gather(*tasks)

# Entry point of the script
if __name__ == "__main__":
    # Run the main asynchronous function
    asyncio.run(main())
