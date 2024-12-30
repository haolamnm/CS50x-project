// Set the initial time in minutes and seconds
let minutes = 50;
let seconds = 0;
let isPaused = true;

// Function to update the timer
function updateTimer() {
	if (!isPaused) {
		// Decrease seconds
		if (seconds === 0) {
			if (minutes === 0) {
				// Stop the timer when it reaches 00:00
				clearInterval(timerInterval);
				return;
			} else {
				minutes--;
				seconds = 59;
			}
		} else {
			seconds--;
		}

		// Format the time as MM:SS
		let formattedMinutes = minutes < 10 ? '0' + minutes : minutes;
		let formattedSeconds = seconds < 10 ? '0' + seconds : seconds;

		// Display the time
		document.getElementById('timer').textContent = formattedMinutes + ':' + formattedSeconds;
	}
}

// Function to toggle the timer
function toggleTimer() {
	isPaused = !isPaused;
	document.getElementById('toggleButton').textContent = isPaused ? 'Start' : 'Pause';
}

// Update the timer every second
let timerInterval = setInterval(updateTimer, 1000);

// Add event listener to the button
document.getElementById('toggleButton').addEventListener('click', toggleTimer);
