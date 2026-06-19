import os
import logging
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from ..models import VECTOR_COLLECTION, VECTOR_INDEX, TOP_K_RAG

logger = logging.getLogger(__name__)


def create_retriever():
    uri = os.getenv("MONGODB_ATLAS_CLUSTER_URI")
    if not uri:
        raise ValueError("MONGODB_ATLAS_CLUSTER_URI no está configurada")

    embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004")

    vector_store = MongoDBAtlasVectorSearch.from_connection_string(
        connection_string=uri,
        namespace=VECTOR_COLLECTION,
        embedding=embeddings,
        index_name=VECTOR_INDEX,
    )

    return vector_store.as_retriever(search_kwargs={"k": TOP_K_RAG})
