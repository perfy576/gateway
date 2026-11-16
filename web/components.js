'use strict';
let componentId=0;
class GatewaySelect extends HTMLElement {
  connectedCallback() {
    if(this.initialized)return;this.initialized=true;
    const options=[...this.querySelectorAll('gw-option')].map(o=>({value:o.getAttribute('value'),text:o.textContent}));
    const name=this.getAttribute('name'),value=this.getAttribute('value') ?? options[0]?.value;
    this.options=options;this.selected=Math.max(0,options.findIndex(o=>o.value===value));this.active=this.selected;
    this.replaceChildren();
    const id='gw-select-'+(++componentId);
    this.input=document.createElement('input');this.input.type='hidden';this.input.name=name;this.input.value=options[this.selected]?.value || '';
    this.toggle=document.createElement('button');this.toggle.type='button';this.toggle.className='select-trigger';
    this.toggle.setAttribute('role','combobox');this.toggle.setAttribute('aria-haspopup','listbox');this.toggle.setAttribute('aria-expanded','false');this.toggle.setAttribute('aria-controls',id);
    this.toggle.setAttribute('aria-labelledby',this.getAttribute('aria-labelledby') || '');
    this.label=document.createElement('span');this.label.textContent=options[this.selected]?.text || '';
    const arrow=document.createElement('i');arrow.dataset.lucide='chevron-down';
    this.toggle.append(this.label,arrow);
    this.list=document.createElement('div');this.list.className='select-options';this.list.id=id;this.list.role='listbox';this.list.hidden=true;
    options.forEach((o,i)=>{
      const button=document.createElement('button');button.type='button';button.id=id+'-'+i;button.role='option';button.tabIndex=-1;
      button.textContent=o.text;button.setAttribute('aria-selected',String(i===this.selected));
      button.addEventListener('click',()=>this.choose(i));this.list.append(button);
    });
    this.append(this.input,this.toggle,this.list);
    this.toggle.addEventListener('click',()=>this.open(!this.list.hidden));
    this.toggle.addEventListener('keydown',event=>{
      if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)) {
        event.preventDefault();if(this.list.hidden)this.open(false);
        this.active=event.key==='Home'?0:event.key==='End'?options.length-1:Math.max(0,Math.min(options.length-1,this.active+(event.key==='ArrowDown'?1:-1)));this.highlight();
      }else if(event.key==='Enter'||event.key===' '){event.preventDefault();if(this.list.hidden)this.open(false);else this.choose(this.active);}
      else if(event.key==='Escape'){event.preventDefault();event.stopPropagation();this.open(true);}
      else if(event.key==='Tab')this.open(true);
      else if(event.key.length===1){const next=options.findIndex(o=>o.text.toLowerCase().startsWith(event.key.toLowerCase()));if(next>=0){this.active=next;this.highlight();}}
    });
    this.outside=event=>{if(!this.contains(event.target))this.open(true);};document.addEventListener('click',this.outside);
  }
  disconnectedCallback(){document.removeEventListener('click',this.outside);}
  open(close){this.list.hidden=close;this.toggle.setAttribute('aria-expanded',String(!close));this.active=this.selected;this.highlight();}
  highlight(){[...this.list.children].forEach((o,i)=>o.classList.toggle('focused',i===this.active));if(!this.list.hidden){this.toggle.setAttribute('aria-activedescendant',this.list.children[this.active]?.id || '');}else this.toggle.removeAttribute('aria-activedescendant');}
  choose(index){this.selected=index;this.input.value=this.options[index].value;this.label.textContent=this.options[index].text;[...this.list.children].forEach((o,i)=>o.setAttribute('aria-selected',String(i===index)));this.open(true);this.toggle.focus();this.dispatchEvent(new Event('change',{bubbles:true}));}
  get value(){return this.input?.value;}
}
class GatewayCheck extends HTMLElement {
  connectedCallback(){
    if(this.initialized)return;this.initialized=true;
    const text=this.textContent;this.replaceChildren();
    const label=document.createElement('label');label.className=this.hasAttribute('toggle')?'check toggle-control':'check';
    const input=document.createElement('input');input.type='checkbox';input.name=this.getAttribute('name') || '';input.value=this.getAttribute('value') || 'on';input.checked=this.hasAttribute('checked');
    input.disabled=this.hasAttribute('disabled');
    if(this.hasAttribute('toggle'))input.setAttribute('role','switch');
    const decoration=document.createElement('span');decoration.className='check-decoration';decoration.setAttribute('aria-hidden','true');
    const caption=document.createElement('span');caption.textContent=text;
    label.append(input,decoration,caption);this.append(label);this.input=input;
  }
  get checked(){return this.input?.checked || false;}
  set checked(value){if(this.input)this.input.checked=Boolean(value);}
}
customElements.define('gw-select',GatewaySelect);
customElements.define('gw-checkbox',GatewayCheck);
