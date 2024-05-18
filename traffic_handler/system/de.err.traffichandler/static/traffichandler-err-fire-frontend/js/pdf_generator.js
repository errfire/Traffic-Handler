var $j = jQuery.noConflict();
function generatePDF(constructionId) {
        $.ajax({
            type: 'GET',
            url: `/generate_pdf/${constructionId}`,
            success: function(response) {
                console.log('PDF generated successfully');
                window.open(`/generate_pdf/${constructionId}`);
                alert('PDF wurde erfolgreich generiert und heruntergeladen.');
            },
            error: function(error) {
                console.error('Error generating PDF:', error.responseText);
                alert('Fehler beim Generieren der PDF');
            }
        });
}
