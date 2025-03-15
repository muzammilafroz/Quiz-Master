// Variables to track the quiz state
let currentQuestion = 1;
let totalQuestions = 0;
let questionStatus = {};
let timerId;
let totalTime = 0;
let remainingTime = 0;
let questionIdToIndex = {}; // Map question IDs to their indexes
let quizEnded = false; // Added to track quiz completion
let isSubmitting = false; // Added to track submission in progress
let isTimeUp = false; // Track if time is up

// Show a specific question and hide others
function showQuestion(questionNumber) {
    // Hide all questions
    document.querySelectorAll('.question-card').forEach(card => {
        card.style.display = 'none';
    });

    // Show the specified question
    const questionCard = document.getElementById(`question-${questionNumber}`);
    if (questionCard) {
        questionCard.style.display = 'block';
        currentQuestion = questionNumber;

        // If this is the first time visiting this question
        if (!questionStatus[questionNumber]) {
            questionStatus[questionNumber] = 'Not Answered';
        }

        updateProgressBar();
        updateQuestionNavigator();
    }
}

// Update the status of a question (Answered, Marked for Review)
function updateQuestionStatus(questionNumber, status) {
    questionStatus[questionNumber] = status;
    updateProgressBar();
    updateQuestionNavigator();
}

// Move to the next or previous question
function navigateQuestion(direction) {
    let newQuestion = currentQuestion + direction;
    if (newQuestion >= 1 && newQuestion <= totalQuestions) {
        showQuestion(newQuestion);
    }
}

// Clear the selected answer for the current question
function clearAnswer() {
    const currentQuestionElement = document.getElementById(`question-${currentQuestion}`);
    const radioInputs = currentQuestionElement.querySelectorAll('input[type="radio"]');

    // Uncheck all radio buttons
    radioInputs.forEach(input => {
        input.checked = false;
    });

    // Update status
    updateQuestionStatus(currentQuestion, 'Not Answered');
}

// Update the progress bar and status counts
function updateProgressBar() {
    const answeredCount = Object.values(questionStatus).filter(status => status === 'Answered').length;
    const reviewCount = Object.values(questionStatus).filter(status => status === 'Marked for Review').length;
    const unansweredCount = totalQuestions - answeredCount - reviewCount;

    // Update progress bar
    const progressPercentage = (answeredCount / totalQuestions) * 100;
    document.getElementById('quiz-progress').style.width = `${progressPercentage}%`;

    // Update status counts
    document.getElementById('answered-count').textContent = answeredCount;
    document.getElementById('review-count').textContent = reviewCount;
    document.getElementById('unanswered-count').textContent = unansweredCount;
}

// Update the question navigator to highlight current, answered, and review questions
function updateQuestionNavigator() {
    const navigatorButtons = document.querySelectorAll('.question-navigator button');

    navigatorButtons.forEach(button => {
        const questionNum = parseInt(button.getAttribute('data-question'));

        // Remove all status classes first
        button.classList.remove('btn-primary', 'btn-success', 'btn-warning', 'btn-danger', 'btn-outline-secondary');

        // Apply appropriate class based on status
        if (questionNum === currentQuestion) {
            button.classList.add('btn-primary'); // Current question (blue)
        } else if (questionStatus[questionNum] === 'Answered') {
            button.classList.add('btn-success'); // Answered (green)
        } else if (questionStatus[questionNum] === 'Marked for Review') {
            button.classList.add('btn-warning'); // Marked for review (yellow)
        } else if (questionStatus[questionNum] === 'Not Answered') {
            button.classList.add('btn-danger'); // Not answered (red)
        } else {
            button.classList.add('btn-outline-secondary'); // Not visited
        }
    });
}

// Start the timer for the quiz
function startTimer(minutes) {
    totalTime = minutes * 60; // Convert to seconds
    remainingTime = totalTime;

    const timerElement = document.getElementById('timer');
    const timerProgressBar = document.getElementById('timer-progress');

    timerId = setInterval(() => {
        remainingTime--;

        if (remainingTime <= 0) {
            clearInterval(timerId);
            isTimeUp = true;
            submitQuiz();
            return;
        }

        // Update timer display
        const minutes = Math.floor(remainingTime / 60);
        const seconds = remainingTime % 60;
        timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        // Update progress bar
        const percentage = (remainingTime / totalTime) * 100;
        timerProgressBar.style.width = `${percentage}%`;

        // Change color based on remaining time
        if (percentage < 25) {
            timerProgressBar.classList.remove('bg-success', 'bg-warning');
            timerProgressBar.classList.add('bg-danger');
        } else if (percentage < 50) {
            timerProgressBar.classList.remove('bg-success', 'bg-danger');
            timerProgressBar.classList.add('bg-warning');
        } else {
            timerProgressBar.classList.remove('bg-warning', 'bg-danger');
            timerProgressBar.classList.add('bg-success');
        }
    }, 1000);
}

// Handle radio button selection to update question status
function handleOptionSelection(questionId) {
    // Update status for the current question
    updateQuestionStatus(currentQuestion, 'Answered');
}

// Mark the current question for review
function markForReview() {
    updateQuestionStatus(currentQuestion, 'Marked for Review');
    navigateQuestion(1); // Move to next question
}

function submitQuiz() {
    // Check for unanswered questions only if time is not up
    if (!isTimeUp) {
        const notAnsweredCount = Object.values(questionStatus).filter(status => status === 'Not Answered').length;
        const notVisitedCount = totalQuestions - Object.keys(questionStatus).length;
        const unansweredCount = notAnsweredCount + notVisitedCount;

        if (unansweredCount > 0) {
            const confirmSubmit = confirm(`Warning: You have ${unansweredCount} unanswered question(s). Do you want to submit anyway?`);
            if (!confirmSubmit) {
                return; // Stay on the quiz page if the user cancels
            }
        }
    }

    // Submit the form
    isSubmitting = true; // Set flag before submission
    quizEnded = true;     // Set flag after submission
    if (timerId) {
        clearInterval(timerId);
    }
    document.getElementById('quiz-form').submit();
}

// Make the timer and quiz navigation sticky when scrolling
function setupStickyElements() {
    const timerBar = document.getElementById('timer-container');
    const questionNav = document.getElementById('question-navigator-container');

    if (timerBar) {
        // Make timer sticky on mobile (top of screen)
        window.addEventListener('scroll', function() {
            if (window.innerWidth < 992) { // Bootstrap's lg breakpoint
                if (window.scrollY > 100) {
                    timerBar.classList.add('fixed-top');
                    document.body.style.paddingTop = timerBar.offsetHeight + 'px';
                } else {
                    timerBar.classList.remove('fixed-top');
                    document.body.style.paddingTop = '0';
                }
            } else {
                timerBar.classList.remove('fixed-top');
                document.body.style.paddingTop = '0';
            }
        });
    }
}

// Initialize quiz when document is loaded
document.addEventListener('DOMContentLoaded', function() {
    const questionCards = document.querySelectorAll('.question-card');
    totalQuestions = questionCards.length;

    // Show the first question by default
    if (totalQuestions > 0) {
        showQuestion(1);
    }

    // Set up quiz duration if element exists and has a value
    const quizElement = document.getElementById('quiz-form');
    if (quizElement && quizElement.dataset.duration) {
        startTimer(parseInt(quizElement.dataset.duration));
    }

    // Set up sticky elements
    setupStickyElements();

    // Add event listeners to radio buttons
    document.querySelectorAll('input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const questionId = parseInt(this.name.replace('question_', ''));
            // Update status for the current question number (not the question ID)
            updateQuestionStatus(currentQuestion, 'Answered');
        });
    });

    // Initialize the question navigator (all buttons should be btn-outline-secondary by default)
    document.querySelectorAll('.question-navigator button').forEach(button => {
        button.classList.remove('btn-danger');
        button.classList.add('btn-outline-secondary');
    });

    // Then update based on current status
    updateQuestionNavigator();

    // Add page unload warning except for form submission
    document.getElementById('quiz-form').addEventListener('submit', function() {
        isSubmitting = true;
    });

    window.addEventListener('beforeunload', function(e) {
        if (!quizEnded && !isSubmitting) {
            // Cancel the event
            e.preventDefault();
            // Chrome requires returnValue to be set
            e.returnValue = '';
        }
    });
});