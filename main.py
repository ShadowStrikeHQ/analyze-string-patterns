import argparse
import re
import logging
import pandas as pd
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Identifies and counts occurrences of suspicious string patterns in a text file.")
    parser.add_argument("filepath", help="Path to the text file to analyze.")
    parser.add_argument("-o", "--output", help="Path to save the analysis results as a CSV file (optional).", default=None)
    parser.add_argument("-l", "--log_level", help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.", default="INFO")
    return parser

def analyze_file(filepath):
    """
    Analyzes the given file for suspicious string patterns and returns a pandas DataFrame with the results.
    Args:
        filepath (str): The path to the file to analyze.
    Returns:
        pandas.DataFrame: A DataFrame containing the counts of each pattern found.  Returns None on error.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:  # Explicit encoding for handling different character sets
            text = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading the file: {e}")
        return None
    
    # Regular expressions for suspicious patterns
    patterns = {
        "IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "URL": r"\b(?:https?://|www\.)[^\s]+\b",
        "Hex Encoded": r"\\x[0-9a-fA-F]{2}",  # Matches \x followed by two hexadecimal characters
        "MD5 Hash": r"\b[0-9a-fA-F]{32}\b",
        "SHA1 Hash": r"\b[0-9a-fA-F]{40}\b",
        "SHA256 Hash": r"\b[0-9a-fA-F]{64}\b",
        "Base64 Encoded": r"\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"
    }

    results = {}
    for name, regex in patterns.items():
        try:
            matches = re.findall(regex, text)
            results[name] = len(matches)
        except re.error as e:
            logging.error(f"Regular expression error for {name}: {e}")
            return None  # Or continue, depending on the desired behavior
        except Exception as e:
             logging.error(f"An unexpected error occurred while processing regex {name}: {e}")
             return None # or continue, depending on desired behaviour
    
    df = pd.DataFrame.from_dict(results, orient='index', columns=['Count'])
    df.index.name = 'Pattern'
    return df

def save_results(df, output_path):
    """
    Saves the analysis results to a CSV file.
    Args:
        df (pandas.DataFrame): The DataFrame containing the analysis results.
        output_path (str): The path to save the CSV file.
    """
    try:
        df.to_csv(output_path)
        logging.info(f"Results saved to: {output_path}")
    except IOError as e:
        logging.error(f"Error saving to file {output_path}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while saving the results: {e}")

def main():
    """
    Main function to execute the analysis based on command line arguments.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level based on command line argument
    try:
        logging.getLogger().setLevel(args.log_level.upper())
    except ValueError:
        logging.error("Invalid log level.  Please choose from DEBUG, INFO, WARNING, ERROR, or CRITICAL.")
        return

    filepath = args.filepath

    # Input validation: Check if the file path is valid
    if not os.path.isfile(filepath):
        logging.error(f"Error: The provided file path '{filepath}' is not a valid file.")
        return
    
    logging.info(f"Analyzing file: {filepath}")
    
    df = analyze_file(filepath)
    
    if df is not None:  # Only proceed if analysis was successful
        print(df) # Print to console by default

        if args.output:
            save_results(df, args.output)
    else:
        logging.error("Analysis failed. See log for details.")

if __name__ == "__main__":
    main()