def generate_csv(df,output_path: str,report_name: str):
    import os
    from tqdm import tqdm
    from datetime import datetime
    import pandas as pd

    # Ensure directory exists
    os.makedirs(output_path, exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    csv_file_path = os.path.join(output_path, f"{report_name}_{timestamp}.csv")

    if df.empty:
        with open(csv_file_path, "w") as f:
            f.write("Property,repo_path,severity,tag,subtag,description\n")
            for i in range(400):
                f.write(f"{i+1},empty,empty,empty,empty,empty\n")
        tqdm.write(f"⚠️ CSV generated (empty): {csv_file_path}")
    else:
        df.insert(0, 'Property', range(1, len(df) + 1))

        # Ensure the DataFrame has exactly 400 rows
        if len(df) < 400:
            empty_rows = pd.DataFrame(
                {
                    "Property": range(len(df) + 1, 401),
                    "repo_path": "empty",
                    "severity": "empty",
                    "tag": "empty",
                    "subtag": "empty",
                    "description": "empty",
                }
            )
            df = pd.concat([df, empty_rows], ignore_index=True)
        elif len(df) > 400:
            df = df.iloc[:400]

        df.to_csv(csv_file_path, index=False)
        tqdm.write(f"✅ CSV successfully generated: {csv_file_path}")

    return

