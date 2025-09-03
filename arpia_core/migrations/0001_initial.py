from django.db import migrations, models
import uuid
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('title', models.CharField(max_length=220, unique=True)),
                ('slug', models.SlugField(max_length=220, unique=True)),
                ('summary', models.TextField(blank=True)),
                ('created', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('modified', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ('-created',),
                'verbose_name': 'Projeto',
                'verbose_name_plural': 'Projetos',
            },
        ),
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('identifier', models.CharField(max_length=300, db_index=True)),
                ('name', models.CharField(max_length=300, blank=True)),
                ('hostnames', models.JSONField(default=list, blank=True)),
                ('ips', models.JSONField(default=list, blank=True)),
                ('category', models.CharField(max_length=80, blank=True)),
                ('metadata', models.JSONField(default=dict, blank=True)),
                ('created', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('last_seen', models.DateTimeField(null=True, blank=True)),
                ('project', models.ForeignKey(related_name='assets', on_delete=models.CASCADE, to='arpia_core.project')),
            ],
            options={
                'unique_together': {('project', 'identifier')},
                'ordering': ('-last_seen', '-created'),
                'verbose_name': 'Ativo',
                'verbose_name_plural': 'Ativos',
            },
        ),
        migrations.CreateModel(
            name='ObservedEndpoint',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('ip', models.CharField(max_length=46)),
                ('port', models.PositiveIntegerField()),
                ('proto', models.CharField(max_length=24, blank=True)),
                ('service', models.CharField(max_length=200, blank=True)),
                ('path', models.CharField(max_length=500, blank=True)),
                ('raw', models.JSONField(default=dict, blank=True)),
                ('source', models.CharField(max_length=120, blank=True)),
                ('first_seen', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(related_name='endpoints', null=True, blank=True, on_delete=models.SET_NULL, to='arpia_core.asset')),
            ],
            options={
                'ordering': ('-last_seen', '-first_seen'),
                'verbose_name': 'Endpoint Observado',
                'verbose_name_plural': 'Endpoints Observados',
            },
        ),
        migrations.AddConstraint(
            model_name='observedendpoint',
            constraint=models.UniqueConstraint(fields=['ip', 'port', 'proto', 'source'], name='uniq_endpoint_by_source'),
        ),
    ]