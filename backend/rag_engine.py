# =============================================================
# RAG ENGINE — Retrieval Augmented Generation
# 
# What this does:
# 1. Reads the knowledge base text file
# 2. Splits it into small chunks
# 3. Converts each chunk into a vector (list of numbers)
# 4. When you ask a question, finds the most relevant chunks
# 5. Returns those chunks as context for answering
# =============================================================

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import os

class RAGEngine:
    def __init__(self):
        print("Loading AI model for RAG...")
        # This model converts text into vectors (numbers)
        # Similar text = similar vectors = easy to find related content
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.chunks = []
        self.index = None
        print("RAG model loaded!")

    def load_knowledge_base(self, filepath):
        """Read the knowledge base and split into chunks"""
        with open(filepath, 'r') as f:
            text = f.read()

        # Split by double newline into paragraphs
        raw_chunks = text.split('\n\n')
        
        # Clean and filter chunks
        self.chunks = [c.strip() for c in raw_chunks if len(c.strip()) > 50]
        
        print(f"Loaded {len(self.chunks)} knowledge chunks")
        
        # Convert all chunks to vectors
        print("Creating embeddings...")
        embeddings = self.model.encode(self.chunks)
        embeddings = np.array(embeddings).astype('float32')
        
        # Build FAISS index for fast searching
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(embeddings)
        
        print(f"Knowledge base ready! {len(self.chunks)} chunks indexed.")

    def search(self, query, top_k=4):
        """Find the most relevant chunks for a query"""
        if self.index is None:
            return ["Knowledge base not loaded yet."]
        
        # Convert query to vector
        query_vector = self.model.encode([query])
        query_vector = np.array(query_vector).astype('float32')
        
        # Search for similar chunks
        distances, indices = self.index.search(query_vector, top_k)
        
        # Return the matching chunks
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.chunks):
                results.append({
                    "chunk": self.chunks[idx],
                    "relevance_score": float(1 / (1 + distances[0][i]))
                })
        
        return results

    def answer(self, query):
        """Search knowledge base and format an answer"""
        results = self.search(query, top_k=3)
        
        if not results:
            return "I could not find relevant information in my knowledge base."
        
        # Build answer from relevant chunks
        context_parts = []
        for r in results:
            if r['relevance_score'] > 0.1:
                context_parts.append(r['chunk'])
        
        if not context_parts:
            return "No relevant information found for your query."
        
        return "\n\n".join(context_parts)


# Test it
if __name__ == '__main__':
    rag = RAGEngine()
    rag.load_knowledge_base('/Users/aziniftikhar/soc_assistant/data/threat_knowledge.txt')
    
    print("\n--- Testing RAG ---")
    queries = [
        "What is ransomware?",
        "How do I detect a brute force attack?",
        "What is port 4444 used for?"
    ]
    
    for q in queries:
        print(f"\nQ: {q}")
        print(f"A: {rag.answer(q)[:300]}...")
