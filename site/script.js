document.addEventListener('DOMContentLoaded', () => {

    /* --- Scroll Animations (Intersection Observer) --- */
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const elementObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                // Optional: Stop observing once animated
                // observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    const animatedElements = document.querySelectorAll('.slide-up-element');
    animatedElements.forEach(el => elementObserver.observe(el));


    /* --- Nav Scroll Effect --- */
    const nav = document.getElementById('floating-nav');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            nav.classList.add('scrolled');
        } else {
            nav.classList.remove('scrolled');
        }
    });





    /* --- Copy Button functionality moved to inline script in index.html --- */

    /* --- Bill Counter Animation --- */
    const billCounter = document.getElementById('bill-counter');
    if (billCounter) {
        let currentBill = 0;
        setInterval(() => {
            currentBill += Math.random() * 543.21;
            if (currentBill > 99000) currentBill = 0; // Reset just to keep it looping
            
            // Format as currency
            const formatter = new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: 'USD'
            });
            billCounter.innerText = formatter.format(currentBill);
        }, 150);
    }

    /* --- Interactive Before/After Toggle --- */
    const baToggleButtons = document.querySelectorAll('.ba-toggle .toggle-btn');
    const stateBefore = document.getElementById('state-before');
    const stateAfter = document.getElementById('state-after');
    const toggleBg = document.getElementById('toggle-bg');
    
    if (baToggleButtons.length > 0 && stateBefore && stateAfter) {
        baToggleButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetState = btn.getAttribute('data-target');
                
                // Update buttons
                baToggleButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Update button text color styling base class via parent
                const baToggleWrapper = document.getElementById('ba-toggle');
                
                // Animate background pill & Crossfade DOM states
                if(targetState === 'after') {
                    toggleBg.style.transform = 'translateX(100%)';
                    baToggleWrapper.classList.add('after-active');
                    
                    stateBefore.classList.remove('active');
                    stateAfter.classList.add('active');
                } else {
                    toggleBg.style.transform = 'translateX(0)';
                    baToggleWrapper.classList.remove('after-active');
                    
                    stateAfter.classList.remove('active');
                    stateBefore.classList.add('active');
                }
            });
        });
    }

    /* --- Dynamic IDE Title Typing Effect --- */
    const dynamicIdeElement = document.querySelector('.dynamic-ide');
    if (dynamicIdeElement) {
        const ideList = ["Windsurf.", "Cursor.", "Antigravity.", "your editor."];
        let isTyping = false;
        
        const typeIde = async () => {
            if(isTyping) return;
            isTyping = true;
            
            for(let i = 0; i < ideList.length; i++) {
                const word = ideList[i];
                
                // Type characters one by one
                dynamicIdeElement.textContent = '';
                for(let char of word) {
                    dynamicIdeElement.textContent += char;
                    await new Promise(r => setTimeout(r, 60)); // typing speed
                }
                
                // Wait to read the word
                if(i < ideList.length - 1) {
                    await new Promise(r => setTimeout(r, 1500));
                    
                    // Backspace delete the word
                    while(dynamicIdeElement.textContent.length > 0) {
                        dynamicIdeElement.textContent = dynamicIdeElement.textContent.slice(0, -1);
                        await new Promise(r => setTimeout(r, 30)); // backspace speed
                    }
                    await new Promise(r => setTimeout(r, 300)); // wait before typing next
                }
            }
        };

        const spotlightHeader = document.querySelector('.spotlight-header');
        const ideObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Wait 800ms for the CSS slide-up fade-in to finish before starting to type
                    setTimeout(typeIde, 1000);
                    ideObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.8 });
        
        if(spotlightHeader) ideObserver.observe(spotlightHeader);
    }

});
