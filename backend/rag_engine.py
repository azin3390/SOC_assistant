# =============================================================
# RAG ENGINE — Lightweight Retrieval (TF-IDF based)
#
# What this does:
# 1. Reads the knowledge base text file
# 2. Splits it into small chunks
# 3. Scores each chunk against a query using TF-IDF + cosine similarity
# 4. Returns the most relevant chunks as context for answering
#
# This avoids heavy ML models (torch/sentence-transformers) so it
# fits comfortably within free-tier hosting memory limits (512MB),
# while still giving strong retrieval quality for a knowledge base
# of this size.
# =============================================================
import re
import math
from collections import Counter


STOPWORDS = {
    'a','an','the','is','are','was','were','be','been','being','am',
    'what','who','when','where','why','how','which','this','that','these','those',
    'do','does','did','doing','have','has','had','having',
    'i','you','he','she','it','we','they','me','him','her','us','them',
    'my','your','his','its','our','their',
    'and','or','but','if','not','no','so','than','too','very',
    'to','of','in','on','at','by','for','with','about','against','between',
    'into','through','during','before','after','above','below','from','up','down',
    'can','could','will','would','should','shall','may','might','must',
    'as','also','just','then','there','here','all','any','some','such'
}

def tokenize(text):
    words = re.findall(r'[a-z0-9]+', text.lower())
    return [w for w in words if w not in STOPWORDS and len(w) > 1]


class RAGEngine:
    def __init__(self):
        print("Loading lightweight RAG engine (TF-IDF)...")
        self.chunks = []
        self.chunk_tokens = []
        self.doc_freq = Counter()
        self.idf = {}
        print("RAG engine ready!")

    def load_knowledge_base(self, filepath):
        """Read the knowledge base and split into chunks"""
        with open(filepath, 'r') as f:
            text = f.read()

        raw_chunks = text.split('\n\n')
        self.chunks = [c.strip() for c in raw_chunks if len(c.strip()) > 50]

        print(f"Loaded {len(self.chunks)} knowledge chunks")
        print("Building TF-IDF index...")

        self.chunk_tokens = [tokenize(c) for c in self.chunks]

        # Document frequency: how many chunks contain each word
        self.doc_freq = Counter()
        for tokens in self.chunk_tokens:
            for word in set(tokens):
                self.doc_freq[word] += 1

        n_docs = len(self.chunks)
        self.idf = {
            word: math.log((n_docs + 1) / (freq + 1)) + 1
            for word, freq in self.doc_freq.items()
        }

        print(f"Knowledge base ready! {len(self.chunks)} chunks indexed.")

    def _vectorize(self, tokens):
        """Build a TF-IDF weighted term-frequency dict for a token list"""
        counts = Counter(tokens)
        total = len(tokens) or 1
        return {
            word: (count / total) * self.idf.get(word, 1.0)
            for word, count in counts.items()
        }

    def _cosine_sim(self, vec_a, vec_b):
        common = set(vec_a.keys()) & set(vec_b.keys())
        if not common:
            return 0.0
        dot = sum(vec_a[w] * vec_b[w] for w in common)
        norm_a = math.sqrt(sum(v * v for v in vec_a.values())) or 1
        norm_b = math.sqrt(sum(v * v for v in vec_b.values())) or 1
        return dot / (norm_a * norm_b)

    def search(self, query, top_k=4):
        """Find the most relevant chunks for a query"""
        if not self.chunks:
            return ["Knowledge base not loaded yet."]

        query_tokens = tokenize(query)
        query_vec = self._vectorize(query_tokens)

        scored = []
        for i, tokens in enumerate(self.chunk_tokens):
            chunk_vec = self._vectorize(tokens)
            score = self._cosine_sim(query_vec, chunk_vec)
            scored.append((i, score))

        scored.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in scored[:top_k]:
            results.append({
                "chunk": self.chunks[idx],
                "relevance_score": float(score)
            })
        return results

    def answer(self, query):
        """Search knowledge base and format an answer"""
        results = self.search(query, top_k=3)

        if not results:
            return "I could not find relevant information in my knowledge base."

        context_parts = []
        for r in results:
            if r['relevance_score'] > 0.03:
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
