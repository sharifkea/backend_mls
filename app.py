# filepath: c:\Users\ronys\Documents\RUC\Thesis\backend_mls\app.py  # Adjust path to your server file
@app.route('/groups/<group_id>/messages', methods=['GET'])
def get_group_messages(group_id):
    try:
        # ... existing code ...
        print(f"Fetching messages for group_id: {group_id}")  # Add debug log
        # ... existing code ...
    except Exception as e:
        print(f"Error in get_group_messages: {e}")  # Add error log
        return jsonify({"error": "Internal server error"}), 500