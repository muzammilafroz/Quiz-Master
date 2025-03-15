function createScoreChart(canvasId, labels, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Score History',
                data: data,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

function createSubjectPerformanceChart(canvasId, subjects, averages) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: subjects,
            datasets: [{
                label: 'Average Score by Subject',
                data: averages,
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgb(75, 192, 192)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}
function getThemeColors() {
    const theme = document.getElementById('html-element').getAttribute('data-bs-theme');
    return {
        textColor: theme === 'dark' ? '#f8f9fa' : '#212529',
        gridColor: theme === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
        successColor: '#28a745',
        warningColor: '#ffc107',
        dangerColor: '#dc3545',
        primaryColor: '#007bff'
    };
}

function createScoreChart(canvasId, labels, data) {
    const colors = getThemeColors();
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    // Create gradient for the chart
    const gradientFill = ctx.createLinearGradient(0, 0, 0, 400);
    gradientFill.addColorStop(0, 'rgba(40, 167, 69, 0.6)');
    gradientFill.addColorStop(1, 'rgba(40, 167, 69, 0.05)');
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Score (%)',
                data: data,
                borderColor: colors.successColor,
                backgroundColor: gradientFill,
                borderWidth: 2,
                pointBackgroundColor: colors.successColor,
                pointRadius: 4,
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: colors.gridColor
                    },
                    ticks: {
                        color: colors.textColor
                    }
                },
                x: {
                    grid: {
                        color: colors.gridColor
                    },
                    ticks: {
                        color: colors.textColor
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: colors.textColor
                    }
                }
            }
        }
    });
    
    // Update chart when theme changes
    document.getElementById('theme-toggle').addEventListener('change', function() {
        const newColors = getThemeColors();
        
        chart.options.scales.y.ticks.color = newColors.textColor;
        chart.options.scales.y.grid.color = newColors.gridColor;
        chart.options.scales.x.ticks.color = newColors.textColor;
        chart.options.scales.x.grid.color = newColors.gridColor;
        chart.options.plugins.legend.labels.color = newColors.textColor;
        
        chart.update();
    });
    
    return chart;
}

function createSubjectPerformanceChart(canvasId, labels, data) {
    const colors = getThemeColors();
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Average Score (%)',
                data: data,
                backgroundColor: colors.primaryColor,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: colors.gridColor
                    },
                    ticks: {
                        color: colors.textColor
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: colors.textColor
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: colors.textColor
                    }
                }
            }
        }
    });
    
    // Update chart when theme changes
    document.getElementById('theme-toggle').addEventListener('change', function() {
        const newColors = getThemeColors();
        
        chart.options.scales.y.ticks.color = newColors.textColor;
        chart.options.scales.y.grid.color = newColors.gridColor;
        chart.options.scales.x.ticks.color = newColors.textColor;
        chart.options.plugins.legend.labels.color = newColors.textColor;
        
        chart.update();
    });
    
    return chart;
}

function createPieChart(canvasId, labels, data, colors) {
    const themeColors = getThemeColors();
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors || [
                    themeColors.successColor,
                    themeColors.dangerColor,
                    themeColors.warningColor
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: themeColors.textColor,
                        padding: 20
                    }
                }
            }
        }
    });
    
    // Update chart when theme changes
    document.getElementById('theme-toggle').addEventListener('change', function() {
        const newColors = getThemeColors();
        chart.options.plugins.legend.labels.color = newColors.textColor;
        chart.update();
    });
    
    return chart;
}
