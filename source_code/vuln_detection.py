# 这是最终的检测步骤。共分为两个路线：首先是使用 LLM 对所有发现的潜在漏洞过一遍（应该弄个自动化的 agent 去看）
# 第二个就是正常的路线：先通过 签名的相似度进行匹配，然后对匹配到的再使用LLM 进行二次确认。
import os
import json
import pickle
import Levenshtein
from hydra_utils import *
from utils4 import llm_for_fp_prun
# 先匹配数据流吧

ORIGIN_SLICE_CODE_DIR = "./detection_inter_slice_result/"
SIG_DATABASE = "./sig_database"
KNOWN_VULN_SIG_DB = "./sig_gene_results/signature_results"
VARIANT_VULN_SIG_DB = "./sig_gene_results/variant_signature_results_0105"
POTENTIAL_SINKS_DETECTION_DIR = "./potential_sinks_detection"
DETECTION_REPORT_DIR = "./detection_report"

FINAL_SIG_DB_FROM_KNOWN_VULN = "./sig_database/known/signature_db.json"
FINAL_SIG_DB_FROM_VARIANT = "./sig_database/variant/signature_db.json"

if os.path.exists(FINAL_SIG_DB_FROM_KNOWN_VULN):
    with open(FINAL_SIG_DB_FROM_KNOWN_VULN, "r", encoding="utf-8") as f:
        VULN_SIGNATURE_DATABASE = json.load(f)
else:
    VULN_SIGNATURE_DATABASE = dict()

if os.path.exists(FINAL_SIG_DB_FROM_VARIANT):
    with open(FINAL_SIG_DB_FROM_VARIANT, "r", encoding="utf-8") as f:
        VULN_VARIANT_SIGNATURE_DATABASE = json.load(f)
else:
    VULN_VARIANT_SIGNATURE_DATABASE = dict()



VULN_TYPE_TO_STR_DICT = {
    7: 'File_Include',
    2: 'File_Read',
    1: 'File_Delete',
    12: 'File_Write',
    10: 'XSS',
    4: 'Command_Injection',
    3: 'Code_Injection',
    6: 'File_Upload',
    13: 'Open_Redirect',
    8: 'PHP_Object_Injection',
    9: 'SQL_Injection'
}


STR_TO_VULN_TYPE_DICT = {v: k for k, v in VULN_TYPE_TO_STR_DICT.items()}


def get_sink_location(repo, sink, vuln_type_num):
    potential_sink_pkl = os.path.join(POTENTIAL_SINKS_DETECTION_DIR, f"{repo}.pkl")
    potential_sink_data = pickle.load(open(potential_sink_pkl, "rb"))
    print("db")

    vt_sink_datas = potential_sink_data.get(vuln_type_num, {})
    for vt_sink_data in vt_sink_datas:
        if str(vt_sink_data.node_id) == str(sink):
            return vt_sink_data.file_name, vt_sink_data.lineno

    return None, None



def vuln_signature_database():
    # 收集所有已知漏洞及其变体的签名形成签名库。
    # 读取签名库中的签名 形成全局变量。
    for cve_sig_info in os.listdir(KNOWN_VULN_SIG_DB):
        if not cve_sig_info.endswith("_sig_info"):
            continue
        cve_id = cve_sig_info.replace("_sig_info", "")
        
        cve_sig_path = os.path.join(KNOWN_VULN_SIG_DB, cve_sig_info, f"{cve_id}_prepatch_final_sink_context.json")
        with open(cve_sig_path, "r", encoding="utf-8") as f:
            cve_sig = json.load(f)

        for cross_mode, vt_sinkid in cve_sig.items():
            for vuln_type, sink_sig_dict in vt_sinkid.items():
                if vuln_type not in VULN_SIGNATURE_DATABASE:
                    VULN_SIGNATURE_DATABASE[vuln_type] = []
                for sink_id, sig_list in sink_sig_dict.items():
                    for sig in sig_list:
                        if (sig, cve_id) not in VULN_SIGNATURE_DATABASE[vuln_type]:
                            VULN_SIGNATURE_DATABASE[vuln_type].append((sig, cve_id))
                            # 记录签名的来源信息
                            # FINAL_SIG_DB_FROM_KNOWN_VULN_DETAILS_DB[vuln_type].append({
                            #     "cve_id": cve_id,
                            #     "signature": sig,
                            # })

    with open(FINAL_SIG_DB_FROM_KNOWN_VULN, "w", encoding="utf-8") as f:
        json.dump(VULN_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)

MODEL = ""
def variant_signature_database():
    # 收集所有变体生成的签名，形成变体签名库。
    global VARIANT_VULN_SIG_DB
    VARIANT_VULN_SIG_DB = os.path.join(VARIANT_VULN_SIG_DB, MODEL)
    print(f"[+] Loading variant signature database from {VARIANT_VULN_SIG_DB}")
    for cve_sig_info in os.listdir(VARIANT_VULN_SIG_DB):
        if not cve_sig_info.endswith("_variant_sig_info"):
            continue
        cve_id = cve_sig_info.replace("_variant_sig_info", "")
        
        cve_sig_path = os.path.join(VARIANT_VULN_SIG_DB, cve_sig_info, f"{cve_id}_prepatch_final_sink_context.json")
        if not os.path.exists(cve_sig_path):
            continue
        with open(cve_sig_path, "r", encoding="utf-8") as f:
            cve_sig = json.load(f)

        for cross_mode, vt_sinkid in cve_sig.items():
            for vuln_type, sink_sig_dict in vt_sinkid.items():
                if vuln_type not in VULN_VARIANT_SIGNATURE_DATABASE:
                    VULN_VARIANT_SIGNATURE_DATABASE[vuln_type] = []
                for sink_id, sig_list in sink_sig_dict.items():
                    for sig in sig_list:
                        if (sig, cve_id) not in VULN_VARIANT_SIGNATURE_DATABASE[vuln_type]:
                            VULN_VARIANT_SIGNATURE_DATABASE[vuln_type].append((sig, cve_id))

    with open(FINAL_SIG_DB_FROM_VARIANT, "w", encoding="utf-8") as f:
        json.dump(VULN_VARIANT_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)


def clean_vuln_variant_sigdb():
    # 去掉签名中不包含 $source 字符的签名
    for vuln_type in VULN_VARIANT_SIGNATURE_DATABASE:
        cleaned_sigs = []
        for sig_tuple in VULN_VARIANT_SIGNATURE_DATABASE[vuln_type]:
            sig = sig_tuple[0][0]
            if "$Source" in sig:
                cleaned_sigs.append(sig_tuple)
        VULN_VARIANT_SIGNATURE_DATABASE[vuln_type] = cleaned_sigs

def clean_vuln_known_sigdb():
    # 去掉签名中不包含 $source 字符的签名
    for vuln_type in VULN_SIGNATURE_DATABASE:
        cleaned_sigs = []
        for sig_tuple in VULN_SIGNATURE_DATABASE[vuln_type]:
            sig = sig_tuple[0][0]
            if "$Source" in sig:
                cleaned_sigs.append(sig_tuple)
        VULN_SIGNATURE_DATABASE[vuln_type] = cleaned_sigs


def sig_match(vuln_type, potential_signature, signature_db=None):
    # if signature_db is None:
    #     signature_db = VULN_SIGNATURE_DATABASE
    # 对给定的 signature 在 signature_db 中进行匹配，返回匹配结果
    # signature_db 是一个字典，key 是 vuln_type，value 是该类型下的所有签名列表
    vuln_type_to_matched_sigs = dict()
    for vt, sig_list in signature_db.items():
        # 这里使用简单的字符串相似度进行匹配，可以根据需要替换为更复杂的算法
        for sig_tuple in sig_list:
            cve_id = sig_tuple[1]
            sigs = sig_tuple[0]
            for sig in sigs:
                for psig in potential_signature:
                    if "$Source" not in psig :
                        continue
                    similarity_score = Levenshtein.jaro(psig, sig)
                    # print(f"Comparing potential sig: {psig} \n with known sig: {sig} \n| similarity: {similarity_score}|\n")
                    if similarity_score >= 0.85:  # 设置一个阈值
                        # if vuln_type not in vuln_type_to_matched_sigs:
                        #     vuln_type_to_matched_sigs[vuln_type] = []
                        # vuln_type_to_matched_sigs[vuln_type].append((potential_signature, sig, similarity_score))
                        return True, potential_signature, sig, similarity_score, cve_id
    return False, None, None, None, None



def vuln_clone_detection(target_repo_path):
    VARINT_DETECTION = True

    if VARINT_DETECTION:
        sig_DB = VULN_VARIANT_SIGNATURE_DATABASE
    else:
        sig_DB = VULN_SIGNATURE_DATABASE

    report_path = os.path.join(DETECTION_REPORT_DIR, f"{target_repo_path}_detection_report_{'variant' if VARINT_DETECTION else 'original'}.json")
    if os.path.exists(report_path):
        banner_print(f"[+] Detection report already exists at {report_path}, loading...")
        return report_path

    # 对目标仓库进行漏洞签名匹配，找出可能存在的漏洞位置
    detection_signature_db_path = "./detection_intra_slice_result_signature"
    # 读取目标数据库签名位置。
    target_repo_signature_path = os.path.join(detection_signature_db_path, f"{target_repo_path}_prepatch_final_sink_context.json")    
    
    with open(target_repo_signature_path, "r", encoding="utf-8") as f:
        target_repo_signatures = json.load(f)

    # matched sig record
    matched_sig_record = dict()  # vuln_type -> list of (potential_signature, matched_signature, score)

    # 对每个签名进行匹配
    repo = f"{target_repo_path}_prepatch"
    for cross_mode, vt_sinkid in target_repo_signatures.items():
        for vuln_type, sink_sig_dict in vt_sinkid.items():
            for sink_id, sig_dict in sink_sig_dict.items():
                # print(type(sig_dict))
                if type(sig_dict) is not dict:
                    continue
                for potention_vuln_sink_path, sig_context in sig_dict.items():
                    code_vuln_type = potention_vuln_sink_path.split("/")[-2]
                    file_idx = potention_vuln_sink_path.split("/")[-1]
                    origin_sink_id = file_idx.split("_")[0]
                    origin_sink_code_path = os.path.join(ORIGIN_SLICE_CODE_DIR, repo, vuln_type, f"sink_{origin_sink_id}", f"src_sink_path_{file_idx}")
                    # if STR_TO_VULN_TYPE_DICT.get(code_vuln_type) != int(vuln_type):
                    #     continue  # 类型不匹配，跳过
                    for sig in sig_context:
                        matched, potention_sig, matched_sig, score, cve_id = sig_match(vuln_type, sig, sig_DB)
                        if matched:
                            print(f"[+] Potential vulnerability found in {potention_vuln_sink_path}")
                            print(f"    Origin sink code path: {origin_sink_code_path}")
                            print(f"    Potential Signature: {potention_sig}")
                            print(f"    Matched Signature: {matched_sig}")
                            print(f"    Similarity Score: {score}")
                            print(f"    origin CVE ID: {cve_id}")
                            # 记录下这个可能存在漏洞的位置，后续使用 LLM 进行二次确认
                            if code_vuln_type not in matched_sig_record:
                                matched_sig_record[code_vuln_type] = []
                            matched_sig_record[code_vuln_type].append({
                                "potential_signature": potention_sig,
                                "matched_signature": matched_sig,
                                "similarity_score": score,
                                "origin_sink_code_path": origin_sink_code_path,
                                "origin_sink_id": origin_sink_id,
                                "repo": repo,
                                "sink_path": potention_vuln_sink_path,
                                "origin_cve_id": cve_id
                            })

    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(matched_sig_record, f, indent=4, ensure_ascii=False)

    banner_print(f"[+] Detection report saved to {report_path}")
    return report_path

# VULN_TYPE_DICT = {
#     1: 'File_Delete',
#     2: 'File_Read',
#     3: 'Code_Injection',
#     4: 'Command_Injection',
#     6: 'File_Upload',
#     7: 'File_Include',
#     9: 'SQL_Injection',
#     10: 'XSS',
#     12: 'File_Write'
# }
def FP_reduce_prepare(matched_sig_record_path):
    matched_sig_record = json.load(open(matched_sig_record_path, "r", encoding="utf-8"))
    fp_analysis = []  # 用于存储误报分析结果
    for vuln_type, sig_records in matched_sig_record.items():
        for record in sig_records:
            origin_vuln_code_path = record["origin_sink_code_path"]
            origin_sink = record["origin_sink_id"]
            repo = record["repo"]
            vuln_type_num = STR_TO_VULN_TYPE_DICT.get(vuln_type)
            origin_sink_file, origin_sink_lineno = get_sink_location(repo, origin_sink, vuln_type_num)
            # 读取源代码片段    
            if "/9/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/9/", "/SQL_Injection/")
            elif "/10/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/10/", "/XSS/")
            elif "/2/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/2/", "/File_Read/")
            elif "/1/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/1/", "/File_Delete/")
            elif "/12/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/12/", "/File_Write/")
            elif "/4/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/4/", "/Command_Injection/")
            elif "/3/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/3/", "/Code_Injection/")
            elif "/7/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/7/", "/File_Include/")
            elif "/6/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/6/", "/File_Upload/")

            try:
                origin_context = extract_file_function([Path(origin_vuln_code_path)])
                context_content = {k: sorted(list(v)) for k, v in origin_context.items()}     
                if context_content == {}:
                    context_content = {origin_vuln_code_path: []}
                fp_analysis.append({
                    "vuln_type": vuln_type,
                    "repo": repo,
                    "origin_sink_file": origin_sink_file,
                    "origin_sink_lineno": origin_sink_lineno,
                    "origin_context": context_content,
                })
            except Exception as e:
                print(f"[-] Error extracting context from {origin_vuln_code_path}: {e}")

    fp_report_path = os.path.join(DETECTION_REPORT_DIR, f"{repo}_prepare_for_fp_analysis_report_2.json")
    with open(fp_report_path, "w", encoding="utf-8") as f:
        json.dump(fp_analysis, f, indent=4, ensure_ascii=False)

    return fp_report_path


def main():
    # 写一个 argparse，用来接收参数，指明检测哪个repo
    import argparse
    parser = argparse.ArgumentParser(description="Vulnerability Detection")
    parser.add_argument("--repo", type=str, required=True, help="Specify the repository to detect")
    args = parser.parse_args()
    target_repo = args.repo

    # 先整理已知漏洞签名数据库
    vuln_signature_database()
    clean_vuln_known_sigdb()
    # 再整理变体生成的签名数据库
    variant_signature_database()
    clean_vuln_variant_sigdb()


    # 统计已知签名库和变体签名库的大小
    for vuln_type in VULN_SIGNATURE_DATABASE:
        known_count = len(VULN_SIGNATURE_DATABASE.get(vuln_type, []))
        variant_count = len(VULN_VARIANT_SIGNATURE_DATABASE.get(vuln_type, []))
        print(f"[+] Vulnerability Type: {vuln_type} | Known Signatures: {known_count} | Variant Signatures: {variant_count}")


    # matched_sig_record_path = vuln_clone_detection("lms")
    # matched_sig_record_path = ""
    # FP_reduce_prepare(matched_sig_record_path)
    report_path = vuln_clone_detection(target_repo)
    fp_report_path = FP_reduce_prepare(report_path)

    llm_for_fp_prun(target_repo, fp_report_path)


if __name__ == "__main__":
    main()

