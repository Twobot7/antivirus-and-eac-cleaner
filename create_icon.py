from PIL import Image, ImageDraw

def create_scanner_icon():
    # Create a new image with a white background
    size = (256, 256)
    image = Image.new('RGBA', size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a simple magnifying glass
    # Handle
    draw.rectangle([160, 160, 200, 220], fill=(76, 175, 80))
    
    # Glass circle
    draw.ellipse([50, 50, 150, 150], outline=(76, 175, 80), width=10)
    
    # Save as ICO
    image.save('scanner.ico', format='ICO')

if __name__ == "__main__":
    create_scanner_icon() 