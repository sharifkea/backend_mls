def test_direct_db_query():
    """Test the database directly"""
    import asyncpg
    import asyncio
    import base64
    
    async def test():
        conn = await asyncpg.connect("postgresql://postgres:2409@localhost/mls_db")
        try:
            # Your group ID from the output
            group_id_b64 = "ojAa2Q8VMpK6qBZVVIQJlw=="
            group_id_bytes = base64.b64decode(group_id_b64)
            
            # Test the function
            result = await conn.fetch(
                "SELECT * FROM get_group_messages($1, $2, $3, $4)",
                group_id_bytes, 
                "alice_user_id",  # Replace with actual Alice UUID
                None, 
                10
            )
            print(f"Function returned {len(result)} rows")
            for row in result:
                print(f"  - Message from leaf {row['sender_leaf_index']}")
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            await conn.close()
    
    asyncio.run(test())

if __name__ == "__main__":
    test_direct_db_query()
    
## returns
#$ python test_env.py
#['__annotations__', '__class__', '__dataclass_fields__', '__dataclass_params__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__match_args__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'content_aad', 'decrypt_content', 'decrypt_private_message', 'decrypt_sender_data', 'deserialize', 'new', 'sender_aad', 'serialize']
#(self, group_id: mls_stuff.Misc._vl_bytes.VLBytes, epoch: int, content_type: mls_stuff.Enums._content_type.ContentType, authenticated_data: mls_stuff.Misc._vl_bytes.VLBytes, encrypted_sender_data: mls_stuff.Misc._vl_bytes.VLBytes, ciphertext: mls_stuff.Misc._vl_bytes.VLBytes) -> None'