-- Delete client records in the correct order to maintain referential integrity
-- First, delete command history records
DELETE FROM command_history 
WHERE server_id = :server_id;

-- Then delete client configuration records
DELETE FROM client_config 
WHERE server_id = :server_id;

-- Finally delete the server record
DELETE FROM servers 
WHERE id = :server_id;

-- Commit the transaction
COMMIT; 