import sys
import inspect
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.MLS import PrivateMessage
print(dir(PrivateMessage))
print(inspect.signature(PrivateMessage.__init__))
## returns
#$ python test_env.py
#['__annotations__', '__class__', '__dataclass_fields__', '__dataclass_params__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__match_args__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'content_aad', 'decrypt_content', 'decrypt_private_message', 'decrypt_sender_data', 'deserialize', 'new', 'sender_aad', 'serialize']
#(self, group_id: mls_stuff.Misc._vl_bytes.VLBytes, epoch: int, content_type: mls_stuff.Enums._content_type.ContentType, authenticated_data: mls_stuff.Misc._vl_bytes.VLBytes, encrypted_sender_data: mls_stuff.Misc._vl_bytes.VLBytes, ciphertext: mls_stuff.Misc._vl_bytes.VLBytes) -> None'