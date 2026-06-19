import os
import logging
from langchain_mongodb.chat_message_histories import MongoDBChatMessageHistory
from .models import MEMORY_DATABASE, MEMORY_COLLECTION

logger = logging.getLogger(__name__)


def get_chat_history(session_id: str) -> MongoDBChatMessageHistory:
    uri = os.getenv("MONGODB_ATLAS_CLUSTER_URI")
    if not uri:
        raise ValueError("MONGODB_ATLAS_CLUSTER_URI no está configurada")

    return MongoDBChatMessageHistory(
        connection_string=uri,
        database_name=MEMORY_DATABASE,
        collection_name=MEMORY_COLLECTION,
        session_id=session_id,
    )
