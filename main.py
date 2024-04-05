import time
from PIL.Image import init
from angrutils import *
from hooks.HookLoader import HookLoader
import logging
import os
from IoC.SampleLoader import SampleLoader
import sys
import re
import argparse
report = {}


def config_logger(log_base):
    logging.config.fileConfig('./conf/logger.conf')

if __name__ == '__main__':
    logger = logging.getLogger("IoCAnalysis." + __name__)

    initTime = time.time()*1000.0
    parser = argparse.ArgumentParser(description='IoCAnalysis. Proceso de extracción de IoC a partir de un fichero ejecutable PE o ELF.')
    parser.add_argument('--sample', required=True,
                        help='Ruta absoluta de la muestra a analizar')
    parser.add_argument('--output' , required=True,
                        help='Ruta absoluta de la salida del analizador')
    parser.add_argument('--format', required=False,
                        help='Formatos del fichero de resultados separados por comas. Valores aceptados: JSON, PDF, HTML. Por defecto, PDF.')
    parser.add_argument('--graph', required=False, default=False,
                        help='Indicar con true o false si se quiere el grafo de ejecución como imagen a la salida')

    args = parser.parse_args()

    generate_graph = args.graph == "true"
    sample = args.sample
    output_dir = args.output

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    writeToJSON = False
    writeToPDF = True
    writeToHTML = False
    if args.format:
        if 'PDF' not in args.format.upper().split(','):
            writeToPDF=False
        if 'JSON' in args.format.upper().split(','):
            writeToJSON=True
        if 'HTML' in args.format.upper().split(','):
            writeToHTML=True

    config_logger(output_dir)
    logger.info('Salida configurada en el directorio %s' % output_dir)

    logger.info('Analizando:  [%s] ' % sample)

    exe = SampleLoader.load(path=sample)
    proj = None

    if exe.offset != 0:
        logger.info("Offset encontrado en la posición %x" % exe.offset)
        proj = angr.Project(sample,  load_options={'auto_load_libs': False},
                            main_opts={"backend": "blob", "arch": exe.machine, "base_addr": exe.base_addr,
                                       "entry_point": exe.entry_point, "offset": exe.offset})
    else:
        proj = angr.Project(sample,  load_options={'auto_load_libs': False})

    # Hooking
    for f_hook in exe.hook_symbols:
        if proj.loader.find_symbol(f_hook) is not None:
            proj.hook_symbol(f_hook,HookLoader.get_hook(f_hook))
            logger.debug('Symbol %s Hooked by %s' % (f_hook, proj.hooked_by(proj.loader.find_symbol(f_hook).rebased_addr)))

    cfg = None
    cfg_fast = None

    logger.info('Analizando Control-Flow Graph Emulated')
    initial_state = proj.factory.full_init_state()

    exe.process['CFG'] = 'KO'
    if generate_graph:
        try:

            cfg = proj.analyses.CFGEmulated(initial_state=initial_state, iropt_level=2,
                                                context_sensitivity_level=5,resolve_indirect_jumps=False)

            logger.debug('CFG Emulated finalizado.')
            exe.process['CFG_Emulated'] = 'OK'
            exe.cfg_type= 'CFG Emulated'
        except Exception as error:
            exe.process['CFG_Emulated'] = 'KO'
            logger.error("CFG Emulated fallido!",error)
    else:
        exe.process['CFG'] = '--'

    logger.info('Analizando Control-Flow Graph Fast')
    try:
        cfg_fast = proj.analyses.CFGFast()
        logger.debug('CFG fast finalizado.')
        exe.process['CFG_FAST'] = 'OK'
    except Exception as error:
        exe.process['CFG_FAST'] = 'KO'
        logger.error("CFG fast fallido!", error)

    if generate_graph and cfg:
        logger.debug(
            '(CFG Emulated) Numero de nodos %i y numero de vertices %i' % (cfg.graph.number_of_nodes(), cfg.graph.number_of_edges()))
        exe.process['CFG_Nodes'] = cfg.graph.number_of_nodes()
        exe.process['CFG_Edges'] = cfg.graph.number_of_edges()
        if cfg.graph.number_of_nodes() < 1000:
            exe.cfg_img = os.path.join(output_dir,exe.filename) + "_grph"
            plot_cfg(cfg, exe.cfg_img, format="svg",asminst=True, remove_imports=True, remove_path_terminator=True,color_depth=True)

    exe.get_symbols(proj)
    exe.get_functions(proj)
    exe.get_sections(proj)
    exe.machine = proj.arch.name

    if exe:
        if writeToPDF:
            exe.write_pdf(output_dir)
        if writeToJSON:
            exe.write_json(output_dir)
        if writeToHTML:
            exe.write_html(output_dir)
    else:
        logger.info('No se pudo cargar el fichero %s' % sample)

    if exe.tmp_binary and os.path.exists(exe.tmp_binary):
        os.remove(exe.tmp_binary)

    endTime = time.time() * 1000.0
    logger.info('Ejecución finalizada en %i seg' % ((endTime - initTime)/1000) )
    exit()

    func = proj.kb.functions.function(name="strcmp")
    vr = proj.analyses.VariableRecovery(func, kb=proj.kb)
    variable_manager = vr.variable_manager[func.addr]
    for v in variable_manager.get_variables():
        print(v.name)