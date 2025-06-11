use std::process::Command;
use anyhow::Result;
use std::path::Path;

fn key_gen(i: u32) -> Result<()> {
    println!("🔐 Generating BabyJubJub keys using Node.js script...");
    
    // Get the parent directory path
    let parent_dir = Path::new("..");
    
    // Execute the Node.js script with the correct path
    let output = Command::new("node")
        .current_dir(parent_dir)  // Set working directory to parent
        .arg("scripts/gen_bjj_keys.js")
        .arg(i.to_string())
        .output()?;

    // Check if the command was successful
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to generate keys: {}", error);
    }

    // Print the output
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    println!("✅ Key generation complete!");
    Ok(())
}

fn main() -> Result<()> {
    key_gen(0)?;
    key_gen(1)?;
    key_gen(2)?;
    Ok(())
}
