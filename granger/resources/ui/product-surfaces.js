(()=>{
    'use strict';
    const syncVisibility=()=>{document.body.dataset.documentHidden=String(document.hidden)};
    document.addEventListener('visibilitychange',syncVisibility);
    syncVisibility();
    document.querySelectorAll('.log-viewer').forEach(viewer=>{
        const search=viewer.querySelector('.console-search');
        const entries=Array.from(viewer.querySelectorAll('.console-entry'));
        const empty=viewer.querySelector('.console-no-results');
        const filter=()=>{
            const term=search.value.trim().toLocaleLowerCase();
            let visible=0;
            entries.forEach(entry=>{
                entry.hidden=!entry.textContent.toLocaleLowerCase().includes(term);
                if(!entry.hidden)visible++;
            });
            empty.hidden=visible>0||entries.length===0;
        };
        search.addEventListener('input',filter);
        viewer.querySelector('.console-clear').addEventListener('click',()=>{
            entries.forEach(entry=>entry.remove());
            entries.length=0;
            empty.hidden=false;
            search.value='';
            search.focus();
        });
    });
    document.querySelectorAll('.ui-notice-dismiss').forEach(button=>{
        button.addEventListener('click',()=>button.closest('.ui-notice').remove());
    });
    const menus=Array.from(document.querySelectorAll('.service-menu'));
    const items=menu=>Array.from(menu.querySelectorAll('.service-menu-items a:not([aria-disabled=true])'));
    const place=menu=>{
        const trigger=menu.querySelector('summary').getBoundingClientRect();
        const popup=menu.querySelector('.service-menu-items');
        const height=popup.offsetHeight;
        popup.style.position='fixed';
        popup.style.bottom='auto';
        popup.style.left=Math.max(8,Math.min(trigger.right-popup.offsetWidth,innerWidth-popup.offsetWidth-8))+'px';
        popup.style.top=Math.max(8,Math.min(trigger.top-height-6>=8?trigger.top-height-6:trigger.bottom+6,innerHeight-height-8))+'px';
    };
    menus.forEach(menu=>menu.addEventListener('toggle',()=>{
        if(menu.open){menus.forEach(other=>{if(other!==menu)other.open=false});place(menu)}
        else if(menu.pendingItems){menu.querySelector('.service-menu-items').innerHTML=menu.pendingItems;delete menu.pendingItems}
    }));
    menus.forEach(menu=>menu.addEventListener('keydown',event=>{
        const list=items(menu);
        if(!list.length)return;
        if(event.key==='ArrowDown'||event.key==='ArrowUp'||event.key==='Home'||event.key==='End'){
            event.preventDefault();
            menu.open=true;
            place(menu);
            const index=list.indexOf(document.activeElement);
            const next=event.key==='Home'?0:event.key==='End'?list.length-1:
                (index+(event.key==='ArrowUp'?-1:1)+list.length)%list.length;
            list[next].focus();
        }
    }));
    addEventListener('resize',()=>menus.forEach(menu=>{menu.open=false}));
    addEventListener('scroll',()=>menus.forEach(menu=>{menu.open=false}),{capture:true,passive:true});
    document.addEventListener('click',event=>menus.forEach(menu=>{
        if(menu.open&&!menu.contains(event.target))menu.open=false;
    }));
    document.addEventListener('keydown',event=>{
        if(event.key==='Escape')menus.forEach(menu=>{
            if(menu.open){menu.open=false;menu.querySelector('summary').focus()}
        });
    });
    // Preserve the document, focus and disclosure state during runtime status updates.
    window.grangerUpdateHosting=html=>{
        const incoming=new DOMParser().parseFromString(html,'text/html');
        const current=Array.from(document.querySelectorAll('.hosting-service-card'));
        const next=new Map(Array.from(incoming.querySelectorAll('.hosting-service-card'))
            .map(card=>[card.dataset.serviceId,card]));
        if(!current.length||current.length!==next.size||current.some(card=>!next.has(card.dataset.serviceId)))return false;
        current.forEach(card=>{
            const fresh=next.get(card.dataset.serviceId);
            for(const selector of ['.hosting-service-title','.hosting-address','.hosting-meta']){
                const old=card.querySelector(selector),replacement=fresh.querySelector(selector);
                if(old&&replacement&&old.innerHTML!==replacement.innerHTML)old.innerHTML=replacement.innerHTML;
            }
            const oldError=card.querySelector('.hosting-error'),error=fresh.querySelector('.hosting-error');
            if(oldError&&!error)oldError.remove();
            else if(error){
                if(oldError)oldError.textContent=error.textContent;
                else card.querySelector('.hosting-visibility').before(error.cloneNode(true));
            }
            const counts=card.querySelectorAll('.hosting-details dd');
            fresh.querySelectorAll('.hosting-details dd').forEach((value,index)=>{
                if(counts[index])counts[index].textContent=value.textContent;
            });
            const menu=card.querySelector('.service-menu');
            const markup=fresh.querySelector('.service-menu-items').innerHTML;
            if(menu.open)menu.pendingItems=markup;
            else if(menu.querySelector('.service-menu-items').innerHTML!==markup)
                menu.querySelector('.service-menu-items').innerHTML=markup;
        });
        return true;
    };
})();
