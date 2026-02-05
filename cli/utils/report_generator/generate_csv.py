def generate_csv(df,output_path: str,report_name: str):
    import os
    from tqdm import tqdm
    from datetime import datetime

    # Ensure directory exists
    os.makedirs(output_path, exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    csv_file_path = os.path.join(output_path, f"{report_name}_{timestamp}.csv")

    if df.empty:
        with open(csv_file_path, "w") as f:
            f.write("File Name,Tag,Subtag,Severity,Description\n")
        tqdm.write(f"⚠️ CSV generated (empty): {csv_file_path}")
    else:
        df.to_csv(csv_file_path, index=False)
        tqdm.write(f"✅ CSV successfully generated: {csv_file_path}")

    return

