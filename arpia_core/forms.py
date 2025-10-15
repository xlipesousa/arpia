from django import forms

from .models import Script
from .utils import safe_filename


class ScriptForm(forms.ModelForm):
    filename = forms.CharField(max_length=220, label="Arquivo")
    content = forms.CharField(widget=forms.Textarea(attrs={"rows": 20}), label="Conteúdo")

    class Meta:
        model = Script
        fields = ["name", "description", "filename", "content"]
        labels = {
            "name": "Nome",
            "description": "Descrição",
        }

    def __init__(self, *args, **kwargs):
        self.owner = kwargs.pop("owner", None)
        super().__init__(*args, **kwargs)
        base_class = "form-control"
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css} {base_class}".strip()
        self.fields["description"].widget.attrs.setdefault("rows", 3)
        self.fields["filename"].widget.attrs.setdefault("placeholder", "ex: nmap_scan.sh")
        content_widget = self.fields["content"].widget
        content_css = content_widget.attrs.get("class", "")
        content_widget.attrs["class"] = f"{content_css} {base_class} monospace".strip()

    def clean_filename(self):
        raw = self.cleaned_data["filename"].strip()
        cleaned = safe_filename(raw)
        if not cleaned:
            raise forms.ValidationError("Nome de arquivo inválido.")
        return cleaned

    def clean(self):
        cleaned = super().clean()
        if not self.owner:
            return cleaned
        filename = cleaned.get("filename")
        name = cleaned.get("name")
        qs = Script.objects.filter(owner=self.owner, filename=filename)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if filename and qs.exists():
            self.add_error("filename", "Você já possui um script com este nome de arquivo.")
        if name:
            name_qs = Script.objects.filter(owner=self.owner, name=name)
            if self.instance.pk:
                name_qs = name_qs.exclude(pk=self.instance.pk)
            if name_qs.exists():
                self.add_error("name", "Você já possui um script com este nome.")
        return cleaned
