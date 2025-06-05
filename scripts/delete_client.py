import os
import sys
import mysql.connector
import argparse
from datetime import datetime

def delete_client(server_id):
    """Delete a client and all its related records"""
    try:
        # Database connection parameters
        db_config = {
            'host': '127.0.0.1',
            'user': 'root',
            'password': 'moshe36912',
            'database': 'platform_db'
        }
            
        # Connect to database
        print("Connecting to database...")
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Start transaction
        cursor.execute("START TRANSACTION")
        
        try:
            # Delete command history
            cursor.execute("DELETE FROM command_history WHERE server_id = %s", (server_id,))
            history_count = cursor.rowcount
            
            # Delete client configuration
            cursor.execute("DELETE FROM client_configs WHERE server_id = %s", (server_id,))
            config_count = cursor.rowcount
            
            # Delete server record
            cursor.execute("DELETE FROM servers WHERE id = %s", (server_id,))
            server_count = cursor.rowcount
            
            # Commit transaction
            conn.commit()
            
            print(f"Successfully deleted client {server_id}:")
            print(f"- {history_count} command history records")
            print(f"- {config_count} configuration records")
            print(f"- {server_count} server record")
            
        except Exception as e:
            # Rollback on error
            conn.rollback()
            print(f"Error deleting client: {str(e)}")
            sys.exit(1)
            
        finally:
            cursor.close()
            conn.close()
            
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Delete a client and all its related records')
    parser.add_argument('server_id', type=int, help='ID of the server to delete')
    args = parser.parse_args()
    
    # Confirm deletion
    confirm = input(f"Are you sure you want to delete client {args.server_id} and all its related records? (y/N): ")
    if confirm.lower() != 'y':
        print("Deletion cancelled")
        sys.exit(0)
        
    delete_client(args.server_id)

if __name__ == '__main__':
    main() 