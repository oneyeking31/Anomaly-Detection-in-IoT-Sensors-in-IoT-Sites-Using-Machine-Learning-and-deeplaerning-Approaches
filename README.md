Avec les progrès des technologies de communication modernes, l’échelle d’application de l’internet des objets (IoT) a évolué à un niveau sans précédent, et surtout avec l'avènement de la révolution industrielle ce qui d’autre part pose des menaces à l’écosystème IoT. Les intrusions et les actions malveillantes devenant plus complexes et imprévisibles, le développement d’un système efficace de détection des anomalies, en considérant la nature distribuée des réseaux IoT, reste un défi. 
![image](https://github.com/user-attachments/assets/14846920-79b0-4891-8914-c6e906ded3a0)
Data 

On a pris une dataset qui est un ensemble de données qui se compose de plusieurs fichiers qui contiennent la communication du réseau intelligent, à savoir les protocoles IEC 60870-104 (IEC 104) et IEC 61850 (MMS) sous forme de traces CSV, ainsi que les six attaques Connection-Loss, Dos-attack,
Injection-attack, Rogue-device, Scanning-attack et le Switching-attack.

![image](https://github.com/user-attachments/assets/08b6aa39-59b6-4440-a792-d1cd46c71df1)

Les traces ont été générées à partir de fichiers PCAP en utilisant la sonde de flux IPFIX ou un script d’extraction. Les traces CSV incluent l’horodatage, les adresses IP et les ports des appareils communicants, ainsi qu’une séléction d’en-tete IEC 104 et MMS intéressants pour la surveillance de la
sécurité et la détection d’anomalies. Les ensembles de données ont été obtenus en partie en surveillant la communication de dispositifs ICS réels et en partie en surveillant la communication d’applications ICS virtuelles. Les ensembles de données contiennent à la fois du trafic normal sur quelques jours et
du trafic avec des attaques comme le balayage, la communication, le blocage de commandes, etc

![dataset](https://github.com/user-attachments/assets/909f33b6-a6dd-49ce-bcc2-003e8ebf29af)


Missing Data :

Après l’analyse, on à découvert qu’il existe des données vide qu’on n’utilise pas et d’autres null .

Correlation :

Une matrice de corrélation est un tableau montrant les coefficients de corrélation entre les variables. Chaque cellule du tableau indique la corrélation entre deux variables. Une matrice de corrélation est utilisée pour résumer les données , comme entrée dans une analyse plus avancée, et comme diagnostic pour les analyses avancées [48] . Comme le montre notre matrice de correlation dont on a choisi les
meilleures items parmi eux pour les travailler .

![correlation](https://github.com/user-attachments/assets/c5482ab9-34ee-4ec0-83dd-fe6d3c654fe3)

Features Selection :

La sélection des caractéristiques en python est le processus par lequel vous sélectionnez automatiquement ou manuellement les caractéristiques de l’ensemble de données qui contribuent le plus à la variable de prédiction ou à la sortie que vous intéresse. L’une des principales raisons est que l’apprentissage automatique suit la règle "garbage in garbage out" et c’est pourquoi vous devrez etre
très attentif aux caractéristiques qui sont introduites dans le modèle. N’oubliez pas que toutes les caractéristiques présentées dans votre ensemble de données ne sont pas importantes pour obtenir les meilleures performances du modèle [8], d’où l’importance de la matrice de corrélation qui nous à démontré les caractéristiques importants qu’on vas utiliser dans le trainning et le testing de notre
modèle

![image](https://github.com/user-attachments/assets/7dd3e268-205c-4f43-a329-bf9a746c97d0)


Data Reshapping :

Data Reshapping ou bien le remodelage des données dans R consiste à modifier la facon dont les données sont organisées en lignes et en colonnes. La plupart du temps, le traitement des données dans R s’effectue en prenant les données d’entrée sous la forme d’un cadre de données. Il est facile d’extraire des données des lignes et des colonnes d’un cadre de données, mais il existe des situations ou nous avons besoin du cadre de données dans un format différent de celui dans lequel nous l’avons
recu. R dispose de nombreuses fonctions pour diviser, fusionner et changer les lignes en colonnes et vice-versa dans un cadre de données 


Training :

Train est une méthode permettant de mesurer la précision de votre modèle. Elle est appelée Train parce que vous divisez l’ensemble de données en deux ensembles : un ensemble de formation et un ensemble de test. 80 Vous testez le modèle en utilisant l’ensemble de test.Former le modèle signifie créer le modèle. Tester le modèle signifie tester la précision du modèle . Dans cette partie, nous donnons le trafic normale ( sans attaques )aux modèles pour faire le training afin de détecter l’intrusion.
