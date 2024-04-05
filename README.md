# IoCAnalytics

## Instalación

### Descarga utilizando Git:
   `git clone https://github.com/avecab/IoCAnalytics.git`
   
### Creación Python Environment:
   `python -m venv /path/to/new/virtual/environment`
   
### Activación del entorno:
	Unix: 
		/home/currentUser/development/IoCAnalysis_env/bin/activate
	Windows: 
		C:\Users\currentUser\development\IoCAnalysis_env\Scripts\activate.bat
    	
### Instalación de las librerías:
	Unix: 
		source /home/currentUser/development/IoCAnalysis_env/bin/activate
	Windows: 
		C:\Users\currentUser\development\IoCAnalysis_env\Scripts\activate.bat


## Ejecución
Con el entorno activado:

	python main.py --help

	python main.py --sample {path to sample} --output {output path} --format {pdf|json|html} --graph {true,false}

## Parámetros
    • --sample: Es la ruta absoluta de la muestra a analizar.
    • --output: Directorio donde se almacenarán los ficheros de resultado del análisis. En caso de no existir el directorio, se crea automáticamente.
    • --format (Opcional): Formato de los informes de salida, separados por comas. Valores admitidos: PDF, HTML y JSON. Por defecto, solamente PDF.
    • --graph (Opcional): Flag true o false para incluir la generación del control-flow graph. 

