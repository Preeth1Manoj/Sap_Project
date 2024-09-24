document.addEventListener('DOMContentLoaded', function () {
    var dropdownToggles = document.querySelectorAll('.dropdown-toggle');

    dropdownToggles.forEach(function(toggle) {
        toggle.addEventListener('click', function (e) {
            e.preventDefault();
            var dropdownMenu = this.nextElementSibling;
            dropdownMenu.style.display = (dropdownMenu.style.display === 'block') ? 'none' : 'block';
        });
    });
});
document.addEventListener('DOMContentLoaded', function() {
    // Example of dynamic content loading
    fetch('api/users')
        .then(response => response.json())
        .then(data => {
            document.querySelector('.dashboard-card .mdl-card__supporting-text').innerText = `Total: ${data.total}`;
        });
});
   // Initialize FullCalendar
   document.addEventListener('DOMContentLoaded', function () {
    var calendarEl = document.getElementById('calendar');
    var calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth'
    });
    calendar.render();
});

// Initialize Chart.js for a multi-line chart
var ctx = document.getElementById('lineChart').getContext('2d');
var myChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
        datasets: [{
            label: 'Users',
            data: [78, 69, 80, 86, 48, 65, 90],
            borderColor: 'pink',
            borderWidth: 2,
            fill: false
        },{
            label: 'Courses',
            data: [65, 59, 80, 81, 56, 55, 40],
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 2,
            fill: false
        }, {
            label: 'Enquiries',
            data: [28, 48, 40, 19, 86, 27, 90],
            borderColor: 'rgba(153, 102, 255, 1)',
            borderWidth: 2,
            fill: false
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});
document.addEventListener('DOMContentLoaded', function () {
    // Corrected query selector (removed the space between '.fas' and '.fa-chevron-down')
    var bellIcon = document.querySelector('.fas.fa-chevron-down');
    var dropdownContent = document.querySelector('.dropdown-content');

    bellIcon.addEventListener('click', function () {
        dropdownContent.style.display = dropdownContent.style.display === 'block' ? 'none' : 'block';
    });

    // Close the dropdown if user clicks outside
    window.onclick = function(event) {
        if (!event.target.matches('.fas.fa-chevron-down')) {
            dropdownContent.style.display = 'none';
        }
    };
});


// Dark Theme toggle
themeToggler.addEventListener("click", function(){
    document.body.classList.toggle("dark-theme-variables");

    themeToggler.querySelector("span:nth-child(1)").classList.toggle("active");
    themeToggler.querySelector("span:nth-child(2)").classList.toggle("active");
});
