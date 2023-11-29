## Description

No nosso projeto foi desenvolvido um website de uma loja online que vende exclusivamente produtos alusivos ao DETI. 
Dentro do mesmo é possível criar-se um utilizador e fazer login com o mesmo, pode ainda adicionar os seus produtos preferidos a uma lista de favoritos assim como adiciona-los diretamente ao carrinho de compras. 
Para implementar este site foi usado com base uma aplicação em flask com base em paginas de html e uma base de dados em SQLite.<br> 
Para satisfazer os requisitos do trabalho que nos foi entregue foram criadas duas versões da aplicação, a app.py é a versão que foi sujeita a vários ataques provocados propositalmente para mostrar as suas vulnerabilidades, já a app_sec.py é uma app que foi desenvolvida de modo a ser segura sobre todos os ataques feitos no primeiro caso.<br> 

## Authors

- GABRIEL JANICAS DA SILVA **108689**<br>
- MARTIM HENRIQUES CARVALHO **108749**<br>
- MIGUEL ROSA REIS **108545**<br>
- RAFAEL ANDRE VALENTE LEITE **108257**<br>
- RODRIGO MIGUEL BARROS MOÇO **108939**<br>


## Vulnerabilities

- CWE - 89

- CWE - 79

- CWE - 862

- CWE - 307

- CWE - 20

- CWE - 200

- CWE - 620

- CWE - 756

- CWE - 256

## RUN

1. Create the virtual environment:
```bash
python3 -m venv venv
```
2. Activate the virtual environment (Every time you open a new terminal you need to do this to make the virtual environment the default Python interpreter of this shell):
```bash
source venv/bin/activate
```
or (Windows):
```bash
.\venv\Scripts\activate.ps1
```

3. Install the requirements:
```bash
pip install -r requirements.txt
```

4. Run the application:


```bash
./run.sh app <PORT>
```
or:
```bash
./run.sh app_sec <PORT>
```

&emsp;&emsp;In Windows use instead:

```bash
.\run.bat app <PORT>
```
or:
```bash
.\run.bat app_sec <PORT>
```
5. Access the website:

```bash
http://127.0.0.1:<PORT>
```

6. To generate the database you need to access the following link:

```bash
/generate/all
```