from django import forms

from .models import Script, Tool, Wordlist
from .utils import safe_filename


class ScriptForm(forms.ModelForm):
    filename = forms.CharField(max_length=220, label="Arquivo")
    required_tool_slug = forms.ChoiceField(
        required=False,
        label="Ferramenta requerida",
        choices=[],
        help_text="Selecione a ferramenta cadastrada que este script utiliza.",
    )
    content = forms.CharField(widget=forms.Textarea(attrs={"rows": 20}), label="Conteúdo")

    class Meta:
        model = Script
        fields = ["name", "description", "filename", "required_tool_slug", "content"]
        labels = {
            "name": "Nome",
            "description": "Descrição",
            "required_tool_slug": "Ferramenta requerida",
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

        tool_choices = [("", "— Nenhuma —")]
        if self.owner:
            user_tools = Tool.objects.for_user(self.owner).order_by("name")
            tool_choices.extend([(tool.slug, f"{tool.name} ({tool.slug})") for tool in user_tools])

        current_value = self.initial.get("required_tool_slug") or self.data.get("required_tool_slug")
        if current_value and not any(choice[0] == current_value for choice in tool_choices):
            tool_choices.append((current_value, current_value))

        self.fields["required_tool_slug"].choices = tool_choices

    def clean_filename(self):
        raw = self.cleaned_data["filename"].strip()
        cleaned = safe_filename(raw)
        if not cleaned:
            raise forms.ValidationError("Nome de arquivo inválido.")
        return cleaned

    def clean(self):
        cleaned = super().clean()
        if not self.owner or self.errors:
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


class ToolForm(forms.ModelForm):
    class Meta:
        model = Tool
        fields = ["name", "description", "path", "category"]
        labels = {
            "name": "Nome",
            "description": "Descrição",
            "path": "Caminho executável",
            "category": "Categoria",
        }

    def __init__(self, *args, **kwargs):
        self.owner = kwargs.pop("owner", None)
        super().__init__(*args, **kwargs)
        base_class = "form-control"
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css} {base_class}".strip()
        self.fields["category"].widget.attrs.setdefault("placeholder", "ex: scanner, brute-force")
        self.fields["path"].widget.attrs.setdefault("placeholder", "/usr/bin/nmap")

    def clean_name(self):
        name = self.cleaned_data.get("name", "").strip()
        if not name:
            raise forms.ValidationError("Informe um nome para identificar a ferramenta.")
        return name

    def clean_path(self):
        path = self.cleaned_data.get("path", "").strip()
        if not path:
            raise forms.ValidationError("Informe o caminho completo do executável.")
        return path

    def clean(self):
        cleaned = super().clean()
        if not self.owner or self.errors:
            return cleaned
        name = cleaned.get("name")
        if name:
            qs = Tool.objects.filter(owner=self.owner, name=name)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                self.add_error("name", "Você já cadastrou uma ferramenta com este nome.")
        return cleaned


class WordlistForm(forms.ModelForm):
    class Meta:
        model = Wordlist
        fields = ["name", "description", "path", "category", "tags"]
        labels = {
            "name": "Nome",
            "description": "Descrição",
            "path": "Caminho do arquivo",
            "category": "Categoria",
            "tags": "Tags",
        }

    tags = forms.CharField(
        label="Tags",
        required=False,
        help_text="Separe por vírgulas. Ex: web, passwords",
    )

    def __init__(self, *args, **kwargs):
        self.owner = kwargs.pop("owner", None)
        super().__init__(*args, **kwargs)
        base_class = "form-control"
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css} {base_class}".strip()
        self.fields["tags"].widget.attrs.setdefault("placeholder", "ex: web, brute, rockyou")
        self.fields["path"].widget.attrs.setdefault("placeholder", "/usr/share/wordlists/rockyou.txt")

        if self.instance.pk and isinstance(self.instance.tags, list):
            self.initial.setdefault("tags", ", ".join(self.instance.tags))

    def clean_name(self):
        name = self.cleaned_data.get("name", "").strip()
        if not name:
            raise forms.ValidationError("Informe um nome para a wordlist.")
        return name

    def clean_path(self):
        path = self.cleaned_data.get("path", "").strip()
        if not path:
            raise forms.ValidationError("Informe o caminho do arquivo da wordlist.")
        return path

    def clean_tags(self):
        raw = self.cleaned_data.get("tags", "")
        if not raw:
            return []
        tags = [tag.strip() for tag in raw.split(",") if tag.strip()]
        return tags

    def clean(self):
        cleaned = super().clean()
        if not self.owner or self.errors:
            return cleaned
        name = cleaned.get("name")
        if name:
            qs = Wordlist.objects.filter(owner=self.owner, name=name)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                self.add_error("name", "Você já possui uma wordlist com este nome.")
        return cleaned
