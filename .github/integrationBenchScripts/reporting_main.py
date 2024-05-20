import argparse, json
from pprint import pprint
import reporting_modules as rmod

env = json.load(open('/etc/taiko/env.json'))
cstats = './cpu.stats'
mstats = './mem.stats'

def main():
    parser = argparse.ArgumentParser(
                    prog = 'BenchmarkResults',
                    usage = 'python3 reporting_main.py logfile 13 EVM 19',
                    description = 'Writes circuit benchmark results to postgresql, uploads logfiles to s3 bucket',
                    )
    parser.add_argument('logfile')
    parser.add_argument('pr')
    parser.add_argument('prover')
    parser.add_argument('degree')
    parser.add_argument('test_id')
    parser.add_argument('instance_commitments')
    parser.add_argument('instance_evaluations')
    parser.add_argument('advice_commitments')
    parser.add_argument('advice_evaluations')
    parser.add_argument('fixed_commitments')
    parser.add_argument('fixed_evaluations')
    parser.add_argument('lookups_commitments')
    parser.add_argument('lookups_evaluations')
    parser.add_argument('equality_commitments')
    parser.add_argument('equality_evaluations')
    parser.add_argument('vanishing_commitments')
    parser.add_argument('vanishing_evaluations')
    parser.add_argument('multiopen_commitments')
    parser.add_argument('multiopen_evaluations')
    parser.add_argument('polycom_commitments')
    parser.add_argument('polycom_evaluations')
    parser.add_argument('circuit_cost')
    parser.add_argument('minimum_rows')
    parser.add_argument('blinding_factors')
    parser.add_argument('gates_count')
    args = parser.parse_args()
    logfile, pr, prover, degree, test_id = (args.logfile, args.pr, args.prover, args.degree, args.test_id)
    instance_commitments, instance_evaluations = (args.instance_commitments, args.instance_evaluations)
    advice_commitments, advice_evaluations = (args.advice_commitments, args.advice_evaluations)
    fixed_commitments, fixed_evaluations  = (args.fixed_commitments, args.fixed_evaluations)
    lookups_commitments, lookups_evaluations = (args.lookups_commitments, args.lookups_evaluations)
    equality_commitments, equality_evaluations = (args.equality_commitments, args.equality_evaluations)
    vanishing_commitments, vanishing_evaluations = (args.vanishing_commitments, args.vanishing_evaluations)
    multiopen_commitments, multiopen_evaluations = (args.multiopen_commitments, args.multiopen_evaluations)
    polycom_commitments, polycom_evaluations = (args.polycom_commitments, args.polycom_evaluations)
    circuit_cost = args.circuit_cost
    minimum_rows, blinding_factors, gates_count = (args.minimum_rows, args.blinding_factors, args.gates_count)
    test_result = rmod.log_processor(pr, degree)
    cpustats, memstats, sysstat = rmod.calc_stats(cstats,mstats)
    data = rmod.prepare_result_dataframe(prover, degree, logfile, test_result, sysstat, env, test_id, instance_commitments, instance_evaluations, advice_commitments, advice_evaluations, fixed_commitments, fixed_evaluations, lookups_commitments, lookups_evaluations, equality_commitments, equality_evaluations, vanishing_commitments, vanishing_evaluations, multiopen_commitments, multiopen_evaluations, polycom_commitments, polycom_evaluations, circuit_cost, minimum_rows, blinding_factors, gates_count)
    table = 'testresults_integration_benchmark'
    engine = rmod.pgsql_engine(env['db'])
    data.to_sql(table,engine,if_exists='append')
    ms = rmod.write_mem_time(engine,memstats, test_id)
    cs = rmod.write_cpuall_time(engine,cpustats, test_id)

    # url = f'{env["grafana_dashboard_prefix"]}{test_id}'.replace(" ", "")
    # print(f'Test Result: {url}')

if __name__ == '__main__':
    main()

