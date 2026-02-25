# test_leafnode_import.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

print("=== Step 9: Importing LeafNode & friends ===\n")

try:
    from mls_stuff.RatchetTree._leaf_node import LeafNode, LeafNodePayload, LeafNodeTBS
    from mls_stuff.Enums import LeafNodeSource
    print("SUCCESS: Imported LeafNode, LeafNodePayload, LeafNodeTBS from RatchetTree._leaf_node")

    print("\nLeafNodeSource values:")
    for name in dir(LeafNodeSource):
        if not name.startswith("_"):
            print(f"  {name} = {getattr(LeafNodeSource, name)}")

    # Check if we can instantiate minimal payload (will fail, but shows required args)
    print("\nTrying minimal LeafNodePayload (expect TypeError):")
    try:
        payload = LeafNodePayload()
        print("Unexpected success?")
    except TypeError as e:
        print("Expected failure:", str(e))

except ImportError as e:
    print("Import failed:", e)
    print("Try adjusting: from mls_stuff.RatchetTree import LeafNode")