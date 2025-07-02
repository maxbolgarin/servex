
// Servex Static Files Demo
console.log('🚀 Servex static file loaded successfully!');

document.addEventListener('DOMContentLoaded', function() {
    console.log('📁 Static files demo ready');
    
    // Add some interactivity
    const title = document.querySelector('h1');
    if (title) {
        title.addEventListener('click', function() {
            this.style.color = this.style.color === 'rgb(231, 76, 60)' ? '#2c3e50' : '#e74c3c';
        });
    }
    
    // Fetch and display file info
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            console.log('📊 Available files:', data.files);
        })
        .catch(err => console.error('❌ Error fetching files:', err));
});
