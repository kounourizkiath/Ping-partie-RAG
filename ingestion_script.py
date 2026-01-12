import os
import shutil
from glob import glob
import warnings

# Filtrage des avertissements de parsing PDF pour nettoyer la sortie du terminal
warnings.filterwarnings("ignore", category=UserWarning, module='pypdf') 

# Importations LangChain mises à jour
from langchain_community.document_loaders import PyPDFLoader, TextLoader, DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

# ==============================================================================
# 1. CONFIGURATION DU PROJET
# ==============================================================================

# Le répertoire racine contenant tous les documents à ingérer (PDF, TXT, etc.)
DATA_DIR = "data"

# Le répertoire où ChromaDB stockera physiquement les vecteurs.
CHROMA_DB_DIR = "vectordb"

# Le nom de la collection (l'équivalent d'une table) dans ChromaDB.
COLLECTION_NAME = "secops_documentation_ping56"

# Modèle d'embedding choisi pour la vectorisation.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Extensions de fichiers supportées
SUPPORTED_EXTENSIONS = ['.pdf', '.txt']

# ==============================================================================
# 2. PARAMÈTRES DE CHUNKING (MEILLEURES PRATIQUES RAG)
# ==============================================================================

# Taille maximale de chaque morceau de texte (chunk) en nombre de caractères.
CHUNK_SIZE = 1000

# Nombre de caractères de chevauchement entre deux chunks consécutifs.
CHUNK_OVERLAP = 200

# ==============================================================================
# 3. FONCTIONS PRINCIPALES DU PIPELINE
# ==============================================================================

def clean_and_prepare_db():
    """
    Fonction de maintenance.
    Supprime le répertoire de la base de données Chroma existante pour garantir
    une nouvelle ingestion propre et à jour.
    """
    if os.path.exists(CHROMA_DB_DIR):
        print(f"🗑️  Suppression de l'ancienne base de données à : {CHROMA_DB_DIR}")
        shutil.rmtree(CHROMA_DB_DIR)
    print("✅ Répertoire de la base de données prêt.\n")

def load_all_documents():
    """
    Fonction de chargement améliorée.
    Recherche et charge tous les fichiers PDF et TXT trouvés récursivement dans le dossier DATA_DIR.
    """
    all_documents = []
    stats = {"pdf": 0, "txt": 0, "errors": 0}
    
    # Recherche de tous les fichiers PDF et TXT
    pdf_files = glob(os.path.join(DATA_DIR, "**", "*.pdf"), recursive=True)
    txt_files = glob(os.path.join(DATA_DIR, "**", "*.txt"), recursive=True)
    
    total_files = len(pdf_files) + len(txt_files)
    
    if total_files == 0:
        print(f"⚠️  ATTENTION : Aucun fichier PDF ou TXT trouvé dans le répertoire '{DATA_DIR}'.")
        return [], stats

    print(f"📚 {len(pdf_files)} fichiers PDF trouvés")
    print(f"📄 {len(txt_files)} fichiers TXT trouvés")
    print(f"📊 Total : {total_files} documents à charger\n")
    
    # Chargement des fichiers PDF
    print("🔄 Chargement des PDFs...")
    for file_path in pdf_files:
        try:
            loader = PyPDFLoader(file_path)
            docs = loader.load()
            all_documents.extend(docs)
            stats["pdf"] += 1
            print(f"  ✓ {os.path.basename(file_path)} ({len(docs)} pages)")
        except Exception as e:
            stats["errors"] += 1
            print(f"  ✗ ERREUR {os.path.basename(file_path)}: {str(e)[:80]}")
    
    # Chargement des fichiers TXT
    print("\n🔄 Chargement des fichiers TXT...")
    for file_path in txt_files:
        try:
            # Utilisation de TextLoader avec encodage UTF-8
            loader = TextLoader(file_path, encoding='utf-8')
            docs = loader.load()
            
            # Ajouter les métadonnées du fichier source
            for doc in docs:
                doc.metadata['source'] = file_path
                doc.metadata['file_type'] = 'txt'
            
            all_documents.extend(docs)
            stats["txt"] += 1
            print(f"  ✓ {os.path.basename(file_path)}")
        except UnicodeDecodeError:
            # Si UTF-8 échoue, essayer avec latin-1
            try:
                loader = TextLoader(file_path, encoding='latin-1')
                docs = loader.load()
                for doc in docs:
                    doc.metadata['source'] = file_path
                    doc.metadata['file_type'] = 'txt'
                all_documents.extend(docs)
                stats["txt"] += 1
                print(f"  ✓ {os.path.basename(file_path)} (encodage latin-1)")
            except Exception as e:
                stats["errors"] += 1
                print(f"  ✗ ERREUR {os.path.basename(file_path)}: {str(e)[:80]}")
        except Exception as e:
            stats["errors"] += 1
            print(f"  ✗ ERREUR {os.path.basename(file_path)}: {str(e)[:80]}")
    
    print(f"\n📈 STATISTIQUES DE CHARGEMENT:")
    print(f"   • PDFs chargés : {stats['pdf']}/{len(pdf_files)}")
    print(f"   • TXTs chargés : {stats['txt']}/{len(txt_files)}")
    print(f"   • Erreurs : {stats['errors']}")
    print(f"   • Total de documents/pages chargés : {len(all_documents)}\n")
    
    return all_documents, stats

def ingest_documents():
    """
    Fonction principale : exécute le pipeline complet d'ingestion RAG.
    """
    print("=" * 80)
    print("🚀 DÉMARRAGE DU PIPELINE D'INGESTION RAG")
    print("=" * 80)
    print(f"📂 Source : {DATA_DIR}")
    print(f"💾 Destination : {CHROMA_DB_DIR}")
    print(f"🏷️  Collection : {COLLECTION_NAME}")
    print(f"🤖 Modèle d'embedding : {EMBEDDING_MODEL}")
    print("=" * 80 + "\n")
    
    # 1. Nettoyage et préparation
    clean_and_prepare_db()
    
    # 2. Chargement de tous les documents
    documents, stats = load_all_documents()
    if not documents:
        print("❌ Arrêt de l'ingestion car aucun document n'a pu être chargé.")
        return

    # 3. Découpage (Chunking)
    print("✂️  Découpage des documents en chunks...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", " ", ""]
    )
    chunks = text_splitter.split_documents(documents)
    print(f"✅ Découpage terminé : {len(chunks)} chunks créés")
    print(f"   • Taille moyenne par chunk : {sum(len(c.page_content) for c in chunks) // len(chunks)} caractères\n")

    # 4. Vectorisation (Embeddings)
    print(f"🧠 Initialisation du modèle d'embedding : {EMBEDDING_MODEL}")
    print("   (Première utilisation : téléchargement du modèle en cours...)")
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    print("✅ Modèle d'embedding prêt\n")

    # 5. Stockage dans ChromaDB
    print(f"💾 Création et persistance de la base de données vectorielle ChromaDB...")
    print(f"   Cela peut prendre quelques minutes pour {len(chunks)} chunks...\n")
    
    vectordb = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=CHROMA_DB_DIR,
        collection_name=COLLECTION_NAME
    )
    
    print("\n" + "=" * 80)
    print("✅ INGESTION TERMINÉE AVEC SUCCÈS")
    print("=" * 80)
    print(f"📊 RÉSUMÉ FINAL:")
    print(f"   • Documents sources : {stats['pdf'] + stats['txt']}")
    print(f"   • PDFs : {stats['pdf']}")
    print(f"   • TXTs : {stats['txt']}")
    print(f"   • Chunks vectorisés : {len(chunks)}")
    print(f"   • Base de données : {CHROMA_DB_DIR}")
    print(f"   • Collection : {COLLECTION_NAME}")
    print("=" * 80)
    print("\n🎉 Votre base de connaissances RAG est maintenant prête à l'emploi !")

# ==============================================================================
# 4. POINT D'ENTRÉE DU SCRIPT
# ==============================================================================

if __name__ == "__main__":
    ingest_documents()