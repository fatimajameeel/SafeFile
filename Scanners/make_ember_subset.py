from pathlib import Path
import pandas as pd


def main():
    # Locate project root and dataset folder
    this_file = Path(__file__).resolve()
    project_root = this_file.parents[1]
    data_dir = project_root / "ML-dataset" / "ember_2018"

    train_path = data_dir / "train_ember_2018_v2_features.parquet"
    print("Loading:", train_path)

    df = pd.read_parquet(train_path)
    print("Full train shape:", df.shape)

    # Sample 100,000 rows from the full dataset
    # This will still contain some unlabeled rows (Label=0),
    # but prepare_ember_xy() will handle that later.
    subset = df.sample(n=100_000, random_state=42)
    print("Subset shape:", subset.shape)

    out_path = data_dir / "train_ember_2018_subset_100k.parquet"
    subset.to_parquet(out_path)
    print("Saved subset to:", out_path)


if __name__ == "__main__":
    main()
