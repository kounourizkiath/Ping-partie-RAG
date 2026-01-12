import os
import json
import time
from datetime import datetime
from typing import List, Dict
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.llms import Ollama
from langchain.prompts import ChatPromptTemplate
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.output_parser import StrOutputParser

# ==============================================================================
# 1. CONFIGURATION
# ==============================================================================

CHROMA_DB_DIR = "vectordb"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
LLM_MODEL = "tinyllama"
TOP_K_RETRIEVAL = 4  # Nombre de chunks à récupérer
RESULTS_FILE = "rag_evaluation_results.json"

# ==============================================================================
# 2. QUESTIONS DE TEST PAR CATÉGORIE
# ==============================================================================

TEST_QUESTIONS = {
    "niveau_1_facile": [
        "Quelles sont les principales méthodes de prévention contre les injections SQL ?",
        "Comment prévenir les attaques XSS (Cross-Site Scripting) ?",
        "Qu'est-ce que CSRF et comment s'en protéger ?",
        "Quelles sont les bonnes pratiques pour le stockage des mots de passe ?",
        "Comment sécuriser une API REST ?",
        "Qu'est-ce que la tactique Initial Access dans MITRE ATT&CK ?",
        "Quelles sont les techniques de Privilege Escalation ?",
        "Qu'est-ce qu'un SIEM et à quoi sert-il ?",
        "Quelles sont les principales fonctionnalités de Splunk ?",
        "Qu'est-ce qu'une règle Sigma ?",
        "Comment fonctionne Microsoft Sentinel ?",
        "Qu'est-ce que la technique T1566 (Phishing) ?",
        "Comment détecter un Lateral Movement ?",
        "Quelles sont les méthodes de Credential Access ?",
        "Comment utiliser Wazuh pour la détection d'intrusion ?",
    ],
    "niveau_2_moyen": [
        "Comment mettre en place une architecture Zero Trust ?",
        "Quelles sont les bonnes pratiques pour sécuriser Docker et Kubernetes ?",
        "Comment implémenter une stratégie DevSecOps efficace ?",
        "Quels sont les composants essentiels d'un SOC ?",
        "Comment centraliser et gérer efficacement les logs de sécurité ?",
        "Quelles sont les étapes d'un processus de threat hunting ?",
        "Comment répondre à une attaque de ransomware ?",
        "Comment analyser une alerte de sécurité dans un SIEM ?",
        "Quelles sont les bonnes pratiques de sécurité pour AWS ?",
        "Comment sécuriser un environnement Azure ?",
        "Quels sont les services de sécurité de Google Cloud Platform ?",
        "Comment implémenter la sécurité des conteneurs en production ?",
        "Quelles sont les phases d'un incident response ?",
        "Comment détecter une compromission Active Directory ?",
        "Quelles différences entre IaaS, PaaS et SaaS en sécurité ?",
    ],
    "niveau_3_difficile": [
        "Je détecte une connexion SSH anormale à 3h du matin depuis une IP étrangère. Quelles sont les étapes d'investigation ?",
        "Comment détecter et bloquer une attaque DDoS avec un SIEM ?",
        "Un utilisateur clique sur un lien de phishing. Quel est le playbook complet ?",
        "Comment investiguer une exfiltration de données via DNS tunneling ?",
        "Quels sont les indicateurs d'une attaque APT ?",
        "Quelle est la différence entre Splunk, Elastic SIEM et Microsoft Sentinel ?",
        "Différence entre règles Sigma et YARA : quand utiliser l'une ou l'autre ?",
        "Quelle est la différence entre un WAF et un IDS/IPS ?",
        "Comment aligner une stratégie avec NIST CSF et ISO 27001 ?",
        "Quelles sont les exigences PCI-DSS pour la protection des données ?",
        "Comment mettre en conformité RGPD un système de logging ?",
        "Quelle est la différence entre CIS Controls et MITRE ATT&CK ?",
        "Comment mapper les contrôles aux tactiques MITRE ATT&CK ?",
        "Comment choisir entre SIEM on-premise ou cloud ?",
        "Avantages et inconvénients de Wazuh vs solutions commerciales ?",
    ],
    "niveau_4_avance": [
        "Comment concevoir une architecture de sécurité multi-cloud avec détection centralisée ?",
        "Quelle stratégie de défense en profondeur pour microservices Kubernetes ?",
        "Comment implémenter une stratégie de threat intelligence avec un SIEM ?",
        "Comment automatiser la réponse aux incidents avec SOAR ?",
        "Comment reconstruire la timeline d'une attaque depuis les logs Splunk ?",
        "Quels artefacts rechercher lors d'une investigation post-compromission Windows ?",
        "Comment détecter une backdoor persistante dans un environnement Linux ?",
        "Comment corréler des événements entre plusieurs sources (SIEM, EDR, Firewall) ?",
        "Quelles techniques de Living off the Land sont difficiles à détecter ?",
        "Comment détecter l'utilisation de Mimikatz ou Cobalt Strike ?",
        "Quelles techniques d'évasion de détection sont les plus courantes ?",
        "Comment mettre en place un purple teaming efficace ?",
        "Quelles métriques pour mesurer la maturité d'un SOC ?",
        "Comment identifier un malware inconnu (zero-day) ?",
        "Quel plan de résilience contre une cyberattaque nation-state ?",
    ]
}

# ==============================================================================
# 3. MOTS-CLÉS ATTENDUS PAR QUESTION (Pour scoring automatique basique)
# ==============================================================================

EXPECTED_KEYWORDS = {
    "injection sql": ["prepared statements", "parameterized", "sanitize", "validation", "escape"],
    "xss": ["encode", "sanitize", "csp", "content security policy", "validate"],
    "csrf": ["token", "same-site", "cookie", "origin"],
    "mot de passe": ["hash", "bcrypt", "salt", "argon", "pbkdf"],
    "api rest": ["authentication", "authorization", "token", "rate limiting", "validation"],
    "initial access": ["phishing", "exploit", "valid accounts", "external remote"],
    "privilege escalation": ["exploit", "bypass", "sudo", "token", "abuse"],
    "siem": ["log", "correlation", "alert", "monitoring", "security"],
    "splunk": ["search", "spl", "index", "event", "correlation"],
    "sigma": ["detection", "rule", "yaml", "generic"],
}

# ==============================================================================
# 4. CLASSE D'ÉVALUATION
# ==============================================================================

class RAGEvaluator:
    def __init__(self):
        self.rag_chain = None
        self.results = {
            "metadata": {
                "date": datetime.now().isoformat(),
                "model": LLM_MODEL,
                "embedding": EMBEDDING_MODEL,
                "top_k": TOP_K_RETRIEVAL
            },
            "categories": {},
            "global_stats": {}
        }
    
    def initialize_rag(self):
        """Initialise la chaîne RAG"""
        print("🔧 Initialisation de la chaîne RAG...")
        
        embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
        vectorstore = Chroma(persist_directory=CHROMA_DB_DIR, embedding_function=embeddings)
        retriever = vectorstore.as_retriever(search_kwargs={"k": TOP_K_RETRIEVAL})
        llm = Ollama(model=LLM_MODEL, temperature=0.1)
        
        template = """
Vous êtes un assistant RAG expert en cybersécurité et SecOps.
Répondez à la question en vous basant UNIQUEMENT sur le contexte fourni.
Si le contexte ne contient pas la réponse, dites "Je ne dispose pas d'informations suffisantes dans ma base de connaissances pour répondre à cette question."
Soyez précis, technique et concis.

Contexte: {context}

Question: {question}

Réponse:"""
        
        prompt = ChatPromptTemplate.from_template(template)
        
        self.rag_chain = (
            {"context": retriever, "question": RunnablePassthrough()}
            | prompt
            | llm
            | StrOutputParser()
        )
        
        print("✅ Chaîne RAG initialisée\n")
    
    def evaluate_response(self, question: str, response: str) -> Dict:
        """Évalue une réponse basique par présence de mots-clés"""
        score = 0
        max_score = 5
        
        response_lower = response.lower()
        
        # Vérifier si c'est une réponse "je ne sais pas"
        no_answer_phrases = [
            "je ne dispose pas",
            "pas d'information",
            "ne contient pas",
            "pas disponible",
            "cannot answer",
            "no information"
        ]
        
        is_no_answer = any(phrase in response_lower for phrase in no_answer_phrases)
        
        if is_no_answer:
            return {
                "score": 0,
                "max_score": max_score,
                "percentage": 0,
                "has_answer": False,
                "response_length": len(response),
                "keywords_found": []
            }
        
        # Scoring basique par longueur de réponse
        response_length = len(response)
        if response_length > 200:
            score += 2
        elif response_length > 100:
            score += 1
        
        # Recherche de mots-clés pertinents
        keywords_found = []
        for keyword_group, keywords in EXPECTED_KEYWORDS.items():
            if any(kw in question.lower() for kw in keyword_group.split()):
                for kw in keywords:
                    if kw in response_lower:
                        keywords_found.append(kw)
                        score += 0.5
        
        # Vérifier si la réponse semble structurée
        if any(marker in response for marker in ["1.", "2.", "-", "•", "*"]):
            score += 1
        
        score = min(score, max_score)
        
        return {
            "score": round(score, 2),
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 1),
            "has_answer": True,
            "response_length": response_length,
            "keywords_found": keywords_found
        }
    
    def test_question(self, question: str, category: str, question_num: int) -> Dict:
        """Teste une question et retourne les résultats"""
        print(f"  [{question_num}] Testing: {question[:60]}...")
        
        start_time = time.time()
        
        try:
            response = self.rag_chain.invoke(question)
            elapsed_time = time.time() - start_time
            
            evaluation = self.evaluate_response(question, response)
            
            result = {
                "question": question,
                "response": response,
                "evaluation": evaluation,
                "time_seconds": round(elapsed_time, 2),
                "success": True,
                "error": None
            }
            
            status = "✅" if evaluation["percentage"] >= 60 else "⚠️" if evaluation["percentage"] >= 30 else "❌"
            print(f"    {status} Score: {evaluation['percentage']}% | Time: {elapsed_time:.2f}s")
            
        except Exception as e:
            result = {
                "question": question,
                "response": None,
                "evaluation": {"score": 0, "max_score": 5, "percentage": 0},
                "time_seconds": 0,
                "success": False,
                "error": str(e)
            }
            print(f"    ❌ ERROR: {str(e)[:50]}")
        
        return result
    
    def run_evaluation(self):
        """Exécute l'évaluation complète"""
        print("="*80)
        print("🚀 DÉMARRAGE DE L'ÉVALUATION RAG SECOPS")
        print("="*80)
        print(f"📅 Date: {self.results['metadata']['date']}")
        print(f"🤖 Modèle LLM: {LLM_MODEL}")
        print(f"🧠 Modèle Embedding: {EMBEDDING_MODEL}")
        print(f"📊 Top K Retrieval: {TOP_K_RETRIEVAL}")
        print("="*80 + "\n")
        
        self.initialize_rag()
        
        total_questions = sum(len(questions) for questions in TEST_QUESTIONS.values())
        current_question = 0
        
        for category, questions in TEST_QUESTIONS.items():
            print(f"\n{'='*80}")
            print(f"📂 CATÉGORIE: {category.upper().replace('_', ' ')}")
            print(f"{'='*80}")
            
            category_results = []
            
            for i, question in enumerate(questions, 1):
                current_question += 1
                result = self.test_question(question, category, current_question)
                category_results.append(result)
                
                # Petite pause pour ne pas surcharger
                time.sleep(0.5)
            
            # Calcul des stats de la catégorie
            successful_tests = [r for r in category_results if r["success"]]
            
            if successful_tests:
                avg_score = sum(r["evaluation"]["percentage"] for r in successful_tests) / len(successful_tests)
                avg_time = sum(r["time_seconds"] for r in successful_tests) / len(successful_tests)
                answers_provided = sum(1 for r in successful_tests if r["evaluation"]["has_answer"])
                
                category_stats = {
                    "total_questions": len(questions),
                    "successful_tests": len(successful_tests),
                    "failed_tests": len(questions) - len(successful_tests),
                    "average_score": round(avg_score, 2),
                    "average_time": round(avg_time, 2),
                    "answers_provided": answers_provided,
                    "no_answer_count": len(successful_tests) - answers_provided
                }
            else:
                category_stats = {
                    "total_questions": len(questions),
                    "successful_tests": 0,
                    "failed_tests": len(questions),
                    "average_score": 0,
                    "average_time": 0,
                    "answers_provided": 0,
                    "no_answer_count": 0
                }
            
            self.results["categories"][category] = {
                "stats": category_stats,
                "questions": category_results
            }
            
            print(f"\n📊 Stats {category}:")
            print(f"   Score moyen: {category_stats['average_score']:.1f}%")
            print(f"   Réponses fournies: {category_stats['answers_provided']}/{category_stats['total_questions']}")
            print(f"   Temps moyen: {category_stats['average_time']:.2f}s")
        
        # Calcul des statistiques globales
        self.calculate_global_stats()
        self.print_final_report()
        self.save_results()
    
    def calculate_global_stats(self):
        """Calcule les statistiques globales"""
        all_successful = []
        total_questions = 0
        
        for category_data in self.results["categories"].values():
            total_questions += category_data["stats"]["total_questions"]
            all_successful.extend([
                q for q in category_data["questions"] if q["success"]
            ])
        
        if all_successful:
            global_avg_score = sum(q["evaluation"]["percentage"] for q in all_successful) / len(all_successful)
            global_avg_time = sum(q["time_seconds"] for q in all_successful) / len(all_successful)
            total_answers = sum(1 for q in all_successful if q["evaluation"]["has_answer"])
            
            # Distribution des scores
            excellent = sum(1 for q in all_successful if q["evaluation"]["percentage"] >= 80)
            good = sum(1 for q in all_successful if 60 <= q["evaluation"]["percentage"] < 80)
            average = sum(1 for q in all_successful if 40 <= q["evaluation"]["percentage"] < 60)
            poor = sum(1 for q in all_successful if q["evaluation"]["percentage"] < 40)
            
            self.results["global_stats"] = {
                "total_questions": total_questions,
                "successful_tests": len(all_successful),
                "failed_tests": total_questions - len(all_successful),
                "global_average_score": round(global_avg_score, 2),
                "global_average_time": round(global_avg_time, 2),
                "total_answers_provided": total_answers,
                "no_answer_total": len(all_successful) - total_answers,
                "score_distribution": {
                    "excellent_80_100": excellent,
                    "good_60_79": good,
                    "average_40_59": average,
                    "poor_0_39": poor
                }
            }
    
    def print_final_report(self):
        """Affiche le rapport final"""
        print("\n" + "="*80)
        print("📊 RAPPORT FINAL D'ÉVALUATION RAG")
        print("="*80)
        
        stats = self.results["global_stats"]
        
        print(f"\n🎯 RÉSULTATS GLOBAUX:")
        print(f"   Questions testées: {stats['total_questions']}")
        print(f"   Tests réussis: {stats['successful_tests']}")
        print(f"   Tests échoués: {stats['failed_tests']}")
        print(f"   Score moyen global: {stats['global_average_score']:.1f}%")
        print(f"   Temps de réponse moyen: {stats['global_average_time']:.2f}s")
        print(f"   Réponses fournies: {stats['total_answers_provided']}/{stats['successful_tests']}")
        
        print(f"\n📈 DISTRIBUTION DES SCORES:")
        dist = stats['score_distribution']
        print(f"   🌟 Excellent (80-100%): {dist['excellent_80_100']}")
        print(f"   👍 Bon (60-79%): {dist['good_60_79']}")
        print(f"   😐 Moyen (40-59%): {dist['average_40_59']}")
        print(f"   ❌ Faible (0-39%): {dist['poor_0_39']}")
        
        print(f"\n📊 PERFORMANCE PAR CATÉGORIE:")
        for category, data in self.results["categories"].items():
            cat_stats = data["stats"]
            print(f"   • {category.replace('_', ' ').title():30s}: {cat_stats['average_score']:5.1f}%")
        
        # Interprétation
        print(f"\n💡 INTERPRÉTATION:")
        if stats['global_average_score'] >= 70:
            print("   ✅ Excellent ! Votre RAG fonctionne très bien.")
        elif stats['global_average_score'] >= 50:
            print("   👍 Bon résultat. Quelques améliorations possibles.")
        elif stats['global_average_score'] >= 30:
            print("   ⚠️  Résultats moyens. Vérifiez le retrieval et les chunks.")
        else:
            print("   ❌ Résultats faibles. Problème de retrieval ou de documents.")
        
        print("\n" + "="*80)
    
    def save_results(self):
        """Sauvegarde les résultats dans un fichier JSON"""
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Résultats sauvegardés dans: {RESULTS_FILE}")
        print(f"📁 Vous pouvez analyser les détails dans ce fichier.\n")

# ==============================================================================
# 5. POINT D'ENTRÉE
# ==============================================================================

def main():
    print("\n" + "="*80)
    print("🔍 ÉVALUATION AUTOMATIQUE DU RAG SECOPS")
    print("="*80)
    print("Ce script va tester votre RAG sur 60 questions réparties en 4 niveaux.")
    print("Cela prendra environ 5-10 minutes selon votre machine.")
    print("="*80 + "\n")
    
    try:
        evaluator = RAGEvaluator()
        evaluator.run_evaluation()
        
        print("\n✅ Évaluation terminée avec succès !")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Évaluation interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()